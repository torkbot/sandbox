use rama_http::HeaderMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestProtocol {
    Http1,
    Http2,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_map_rejects_invalid_header_names() {
        let error = header_map_from_pairs([("bad header", "value")]).unwrap_err();
        assert!(error.contains("invalid header name"));
    }

    #[test]
    fn header_map_preserves_valid_header_values() {
        let headers = header_map_from_pairs([("authorization", "Bearer token")]).unwrap();
        assert_eq!(headers["authorization"], "Bearer token");
    }
}
