//! 基于 OpenSSL 的 TLS 连接器。
//!
//! * 上游站点只支持 TLS 1.2：最高协议版本固定为 1.2（OpenSSL 3.x 默认先发 1.3 握手会失败）
//! * `DEFAULT@SECLEVEL=1`：兼容上游较旧的证书 / 加密套件
//! * 默认校验证书和主机名，只有显式 `verify_tls = false` 才关闭
//! * CA 证书：OpenSSL 默认路径 + `openssl-probe` 探测到的系统证书（SSL_CERT_FILE / SSL_CERT_DIR 优先）。
//!   静态编译的 OpenSSL（vendored）默认路径指向构建目录，不探测系统证书会导致校验失败。

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use ureq::{ReadWrite, TlsConnector};

pub struct OpenSslConnector {
    inner: SslConnector,
    verify: bool,
}

impl OpenSslConnector {
    pub fn new(verify: bool) -> Result<Self, openssl::error::ErrorStack> {
        let mut b = SslConnector::builder(SslMethod::tls_client())?;
        b.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        b.set_cipher_list("DEFAULT@SECLEVEL=1")?;
        if verify {
            let probe = openssl_probe::probe();
            if let Some(file) = &probe.cert_file {
                // 个别路径不可读时忽略，继续尝试其他来源
                let _ = b.load_verify_locations(Some(file), None);
            }
            for dir in &probe.cert_dir {
                let _ = b.load_verify_locations(None, Some(dir));
            }
        } else {
            b.set_verify(SslVerifyMode::NONE);
        }
        Ok(Self {
            inner: b.build(),
            verify,
        })
    }
}

impl TlsConnector for OpenSslConnector {
    fn connect(
        &self,
        dns_name: &str,
        io: Box<dyn ReadWrite>,
    ) -> Result<Box<dyn ReadWrite>, ureq::Error> {
        let cfg = self
            .inner
            .configure()
            .map_err(|e| io::Error::other(format!("TLS 配置失败: {e}")))?
            .verify_hostname(self.verify);
        let stream = cfg.connect(dns_name, io).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("TLS 握手失败: {e}"),
            )
        })?;
        Ok(Box::new(OpenSslStream(stream)))
    }
}

struct OpenSslStream(SslStream<Box<dyn ReadWrite>>);

impl Read for OpenSslStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for OpenSslStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl fmt::Debug for OpenSslStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSslStream").finish_non_exhaustive()
    }
}

impl ReadWrite for OpenSslStream {
    fn socket(&self) -> Option<&TcpStream> {
        self.0.get_ref().socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_system_ca_certificates() {
        // 有系统 CA 文件的环境下（正常的 Linux / macOS 都有），证书库必须非空
        if openssl_probe::probe().cert_file.is_some() {
            let c = OpenSslConnector::new(true).unwrap();
            assert!(!c.inner.context().cert_store().all_certificates().is_empty());
        }
    }

    #[test]
    fn builds_with_and_without_verification() {
        assert!(OpenSslConnector::new(true).is_ok());
        assert!(OpenSslConnector::new(false).is_ok());
    }
}
