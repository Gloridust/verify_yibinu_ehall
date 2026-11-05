//! 与上游 `encrypt.js` 中 `encryptPassword` 等价的 AES-CBC 加密。
//!
//! 明文 = 64 位随机字符 + 原文；key = salt（UTF-8）；IV = 16 位随机字符；PKCS7；Base64 输出。
//! 服务端解密后丢弃前 64 个字符，因此 IV 不需要传给服务端。

use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use rand::Rng;

use crate::error::{AuthError, Result};

const AES_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";

/// 生成上游使用的随机字符串（字符集与 encrypt.js 一致）。
pub fn random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| AES_CHARS[rng.gen_range(0..AES_CHARS.len())] as char)
        .collect()
}

/// 加密密码 / 手机号。密码用表单内的 `pwdEncryptSalt`，手机号用页面的 `frontBackKey`。
pub fn encrypt_password(plain: &str, salt: &str) -> Result<String> {
    let key = salt.trim().as_bytes();
    let iv = random_string(16);
    let data = format!("{}{}", random_string(64), plain);
    encrypt_with_iv(data.as_bytes(), key, iv.as_bytes())
}

fn encrypt_with_iv(data: &[u8], key: &[u8], iv: &[u8]) -> Result<String> {
    macro_rules! enc {
        ($aes:ty) => {
            cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|e| AuthError::InvalidArgument(format!("AES 参数错误: {e}")))?
                .encrypt_padded_vec_mut::<Pkcs7>(data)
        };
    }
    let ct = match key.len() {
        16 => enc!(aes::Aes128),
        24 => enc!(aes::Aes192),
        32 => enc!(aes::Aes256),
        n => {
            return Err(AuthError::InvalidArgument(format!(
                "salt 长度必须为 16/24/32 字节，实际为 {n}"
            )))
        }
    };
    Ok(STANDARD.encode(ct))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockDecryptMut;

    /// 服务端视角解密：IV 任意，丢弃前 64 个字符。
    pub fn decrypt(token: &str, salt: &str) -> String {
        let raw = STANDARD.decode(token).unwrap();
        let plain = cbc::Decryptor::<aes::Aes128>::new_from_slices(salt.as_bytes(), &[b'0'; 16])
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(&raw)
            .unwrap();
        String::from_utf8_lossy(&plain[64..]).into_owned()
    }

    #[test]
    fn roundtrip() {
        let t = encrypt_password("p@ss!word中文", "G9KhHtvLf0t2HKrD").unwrap();
        assert_eq!(decrypt(&t, "G9KhHtvLf0t2HKrD"), "p@ss!word中文");
    }

    #[test]
    fn randomized() {
        let a = encrypt_password("x", "G9KhHtvLf0t2HKrD").unwrap();
        let b = encrypt_password("x", "G9KhHtvLf0t2HKrD").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn bad_salt_len() {
        assert!(encrypt_password("x", "short").is_err());
    }

    #[test]
    fn charset() {
        assert!(random_string(200).bytes().all(|c| AES_CHARS.contains(&c)));
    }
}
