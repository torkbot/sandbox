use rama_http::HeaderMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeaderHookRule {
    pattern: RequestPattern,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestPattern {
    scheme: String,
    authority: String,
    path_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeaderMatch<'a> {
    pub protocol: HttpRequestProtocol,
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub original_destination_ip: &'a str,
    pub upstream_dial_ip: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestProtocol {
    Http1,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestHeaderHookDecision {
    Apply,
    RejectReboundDestination,
    Ignore,
}

impl RequestHeaderHookRule {
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let (scheme, rest) = pattern
            .split_once("://")
            .ok_or_else(|| "request-header hook pattern must include a scheme".to_string())?;
        if scheme != "http" && scheme != "https" {
            return Err("request-header hook pattern scheme must be http or https".to_string());
        }

        let (authority, path) = rest
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or((rest, "/".to_string()));
        if authority.is_empty() {
            return Err("request-header hook pattern authority must not be empty".to_string());
        }

        let path_prefix = path.strip_suffix('*').map(str::to_string).unwrap_or(path);
        if !path_prefix.starts_with('/') {
            return Err("request-header hook pattern path must be absolute".to_string());
        }

        let authority = canonical_authority(scheme, authority)?;

        Ok(Self {
            pattern: RequestPattern {
                scheme: scheme.to_string(),
                authority,
                path_prefix,
            },
        })
    }

    pub fn evaluate(&self, request: &RequestHeaderMatch<'_>) -> RequestHeaderHookDecision {
        let request_authority = match canonical_authority(request.scheme, request.authority) {
            Ok(authority) => authority,
            Err(_) => return RequestHeaderHookDecision::Ignore,
        };
        if self.pattern.scheme != request.scheme
            || self.pattern.authority != request_authority
            || !request.path.starts_with(&self.pattern.path_prefix)
        {
            return RequestHeaderHookDecision::Ignore;
        }

        if is_hostname(&self.pattern.authority)
            && (!is_public_ipv4(request.original_destination_ip)
                || !is_public_ipv4(request.upstream_dial_ip))
        {
            return RequestHeaderHookDecision::RejectReboundDestination;
        }

        RequestHeaderHookDecision::Apply
    }

    pub fn rejects_rebound_authority(
        &self,
        scheme: &str,
        authority: &str,
        original_destination_ip: &str,
        upstream_dial_ip: &str,
    ) -> bool {
        let Ok(authority) = canonical_authority(scheme, authority) else {
            return false;
        };
        self.pattern.scheme == scheme
            && self.pattern.authority == authority
            && is_hostname(&self.pattern.authority)
            && (!is_public_ipv4(original_destination_ip) || !is_public_ipv4(upstream_dial_ip))
    }
}

pub fn header_map_from_pairs<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            name.parse::<rama_http::HeaderName>()
                .map_err(|error| format!("invalid header name: {error}"))?,
            value
                .parse::<rama_http::HeaderValue>()
                .map_err(|error| format!("invalid header value: {error}"))?,
        );
    }
    Ok(headers)
}

fn is_hostname(authority: &str) -> bool {
    let host = authority_host(authority);
    host.parse::<std::net::IpAddr>().is_err()
}

fn canonical_authority(scheme: &str, authority: &str) -> Result<String, String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("request-header hook authority must not be empty".to_string());
    }
    let (host, port) = split_authority(authority);
    let host = host.to_ascii_lowercase();
    match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => Ok(host),
        (_, Some(port)) => Ok(format!("{host}:{port}")),
    }
}

fn authority_host(authority: &str) -> &str {
    split_authority(authority).0
}

fn split_authority(authority: &str) -> (&str, Option<u16>) {
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return (authority, None);
        };
        let host = &authority[..=end];
        let port = authority
            .get(end + 1..)
            .and_then(|rest| rest.strip_prefix(':'))
            .and_then(|port| port.parse().ok());
        return (host, port);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse().ok()),
        _ => (authority, None),
    }
}

fn is_public_ipv4(address: &str) -> bool {
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let octets = address.octets();
    !(octets[0] == 0
        || address.is_loopback()
        || address.is_private()
        || octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
        || address.is_link_local()
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 0
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 2
        || octets[0] == 192 && octets[1] == 88 && octets[2] == 99
        || octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        || octets[0] == 198 && octets[1] == 51 && octets[2] == 100
        || octets[0] == 203 && octets[1] == 0 && octets[2] == 113
        || address.is_unspecified()
        || address.is_multicast()
        || octets[0] >= 240
        || address.is_broadcast())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_rule_matches_expected_authority_and_path() {
        let rule = RequestHeaderHookRule::parse("https://api.github.com/*").unwrap();

        assert_eq!(
            rule.evaluate(&RequestHeaderMatch {
                scheme: "https",
                protocol: HttpRequestProtocol::Http1,
                authority: "api.github.com",
                path: "/user",
                original_destination_ip: "140.82.112.6",
                upstream_dial_ip: "140.82.112.6",
            }),
            RequestHeaderHookDecision::Apply,
        );
    }

    #[test]
    fn request_header_rule_rejects_rebound_private_destination() {
        let rule = RequestHeaderHookRule::parse("https://api.github.com/*").unwrap();

        assert_eq!(
            rule.evaluate(&RequestHeaderMatch {
                scheme: "https",
                protocol: HttpRequestProtocol::Http2,
                authority: "api.github.com",
                path: "/user",
                original_destination_ip: "169.254.169.254",
                upstream_dial_ip: "140.82.112.6",
            }),
            RequestHeaderHookDecision::RejectReboundDestination,
        );
    }

    #[test]
    fn request_header_rule_canonicalizes_authority_for_matching() {
        let rule = RequestHeaderHookRule::parse("https://API.GITHUB.COM:443/*").unwrap();

        assert_eq!(
            rule.evaluate(&RequestHeaderMatch {
                scheme: "https",
                protocol: HttpRequestProtocol::Http1,
                authority: "api.github.com",
                path: "/user",
                original_destination_ip: "140.82.112.6",
                upstream_dial_ip: "140.82.112.6",
            }),
            RequestHeaderHookDecision::Apply,
        );
        assert_eq!(
            rule.evaluate(&RequestHeaderMatch {
                scheme: "https",
                protocol: HttpRequestProtocol::Http1,
                authority: "Api.GitHub.com:443",
                path: "/user",
                original_destination_ip: "140.82.112.6",
                upstream_dial_ip: "140.82.112.6",
            }),
            RequestHeaderHookDecision::Apply,
        );
    }

    #[test]
    fn request_header_rule_rejects_special_use_rebound_destinations() {
        let rule = RequestHeaderHookRule::parse("https://api.github.com/*").unwrap();

        for address in ["100.64.0.1", "198.18.0.1", "240.0.0.1"] {
            assert_eq!(
                rule.evaluate(&RequestHeaderMatch {
                    scheme: "https",
                    protocol: HttpRequestProtocol::Http2,
                    authority: "api.github.com",
                    path: "/user",
                    original_destination_ip: address,
                    upstream_dial_ip: "140.82.112.6",
                }),
                RequestHeaderHookDecision::RejectReboundDestination,
                "{address}",
            );
        }
    }

    #[test]
    fn header_pairs_use_rama_http_header_types() {
        let headers = header_map_from_pairs([("authorization", "Bearer token")]).unwrap();

        assert_eq!(headers["authorization"], "Bearer token");
    }
}
