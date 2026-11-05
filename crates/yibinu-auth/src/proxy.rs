//! 代理环境变量处理。ureq 2 不支持 NO_PROXY，这里自行实现，行为与 Python requests 接近。

fn env_any(names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|n| std::env::var(n).ok())
        .find(|v| !v.trim().is_empty())
}

/// 主机是否命中 NO_PROXY 列表（支持 `*`、精确匹配、域名后缀匹配，忽略 CIDR）。
pub fn host_bypasses_proxy(host: &str, no_proxy: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    no_proxy
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .any(|entry| {
            if entry.is_empty() {
                return false;
            }
            if entry == "*" {
                return true;
            }
            let entry = entry.trim_start_matches("*.").trim_start_matches('.');
            let entry = entry.split(':').next().unwrap_or(entry);
            host == entry || host.ends_with(&format!(".{entry}"))
        })
}

/// 根据环境变量决定访问 `scheme://host` 时使用的代理 URL。
pub fn proxy_for(scheme: &str, host: &str) -> Option<String> {
    if let Some(no_proxy) = env_any(&["NO_PROXY", "no_proxy"]) {
        if host_bypasses_proxy(host, &no_proxy) {
            return None;
        }
    }
    match scheme {
        "https" => env_any(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]),
        _ => env_any(&["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_matching() {
        let np = "localhost,127.0.0.1,.edu.cn, example.org ,10.0.0.0/8";
        assert!(host_bypasses_proxy("localhost", np));
        assert!(host_bypasses_proxy("127.0.0.1", np));
        assert!(host_bypasses_proxy("authserver.yibinu.edu.cn", np));
        assert!(host_bypasses_proxy("a.example.org", np));
        assert!(!host_bypasses_proxy("notexample.org", np));
        assert!(!host_bypasses_proxy("yibinu.com", np));
        assert!(host_bypasses_proxy("anything", "*"));
    }
}
