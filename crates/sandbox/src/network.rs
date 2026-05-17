use std::fmt;
use std::net::IpAddr;

use crate::config::HttpSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub http: Option<HttpPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPlan {
    pub protected_ranges: Vec<CidrRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrRange {
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkError {
    message: String,
}

impl NetworkPlan {
    pub fn from_http(http: Option<&HttpSpec>) -> Result<Option<Self>, NetworkError> {
        let Some(http) = http else {
            return Ok(None);
        };

        Ok(Some(Self {
            http: Some(HttpPlan {
                protected_ranges: http
                    .protected_ranges
                    .iter()
                    .map(|range| CidrRange::parse(range))
                    .collect::<Result<Vec<_>, _>>()?,
            }),
        }))
    }
}

impl CidrRange {
    fn parse(value: &str) -> Result<Self, NetworkError> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| NetworkError::new(format!("invalid CIDR range: {value}")))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| NetworkError::new(format!("invalid CIDR address: {value}")))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| NetworkError::new(format!("invalid CIDR prefix: {value}")))?;

        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix > max_prefix {
            return Err(NetworkError::new(format!("invalid CIDR prefix: {value}")));
        }

        Ok(Self { address, prefix })
    }
}

impl NetworkError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_protected_ranges() {
        let plan = NetworkPlan::from_http(Some(&HttpSpec {
            protected_ranges: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            ca_certificate_pem: None,
            ca_private_key_pem: None,
        }))
        .unwrap()
        .unwrap();

        assert_eq!(plan.http.unwrap().protected_ranges.len(), 2);
    }

    #[test]
    fn rejects_invalid_cidr_prefix() {
        let err = NetworkPlan::from_http(Some(&HttpSpec {
            protected_ranges: vec!["127.0.0.0/33".to_string()],
            ca_certificate_pem: None,
            ca_private_key_pem: None,
        }))
        .unwrap_err();

        assert_eq!(err.to_string(), "invalid CIDR prefix: 127.0.0.0/33");
    }
}
