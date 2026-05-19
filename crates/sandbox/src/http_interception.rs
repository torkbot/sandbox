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
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub original_destination_ip: &'a str,
    pub upstream_dial_ip: &'a str,
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

        let path_prefix = path
            .strip_suffix('*')
            .map(str::to_string)
            .unwrap_or(path);
        if !path_prefix.starts_with('/') {
            return Err("request-header hook pattern path must be absolute".to_string());
        }

        Ok(Self {
            pattern: RequestPattern {
                scheme: scheme.to_string(),
                authority: authority.to_string(),
                path_prefix,
            },
        })
    }

    pub fn evaluate(&self, request: &RequestHeaderMatch<'_>) -> RequestHeaderHookDecision {
        if self.pattern.scheme != request.scheme
            || self.pattern.authority != request.authority
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
    let host = authority.split_once(':').map_or(authority, |(host, _)| host);
    host.parse::<std::net::IpAddr>().is_err()
}

fn is_public_ipv4(address: &str) -> bool {
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast())
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
                authority: "api.github.com",
                path: "/user",
                original_destination_ip: "169.254.169.254",
                upstream_dial_ip: "140.82.112.6",
            }),
            RequestHeaderHookDecision::RejectReboundDestination,
        );
    }

    #[test]
    fn header_pairs_use_rama_http_header_types() {
        let headers = header_map_from_pairs([("authorization", "Bearer token")]).unwrap();

        assert_eq!(headers["authorization"], "Bearer token");
    }
}
