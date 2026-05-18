use std::fmt;

use crate::config::{HttpSpec, NetworkSpec, OutboundRuleSpec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub outbound: Option<OutboundPlan>,
    pub http: Option<HttpPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPlan {
    pub rules: Vec<OutboundRulePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRulePlan {
    AcceptTcp { cidr: CidrRange, ports: Vec<u16> },
    AcceptUdp { cidr: CidrRange, ports: Vec<u16> },
    AcceptPublicInternet { ports: Vec<u16> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPlan {
    pub protected_ranges: Vec<CidrRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrRange {
    net: ipnet::IpNet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkError {
    message: String,
}

impl NetworkPlan {
    pub fn from_spec(network: Option<&NetworkSpec>) -> Result<Option<Self>, NetworkError> {
        let Some(network) = network else {
            return Ok(None);
        };

        Ok(Some(Self {
            outbound: network
                .outbound
                .as_ref()
                .map(|outbound| {
                    outbound
                        .rules
                        .iter()
                        .map(OutboundRulePlan::parse)
                        .collect::<Result<Vec<_>, _>>()
                        .map(|rules| OutboundPlan { rules })
                })
                .transpose()?,
            http: Self::http_plan(network.http.as_ref())?,
        }))
    }

    pub fn from_http(http: Option<&HttpSpec>) -> Result<Option<Self>, NetworkError> {
        let Some(http) = http else {
            return Ok(None);
        };

        Ok(Some(Self {
            outbound: None,
            http: Self::http_plan(Some(http))?,
        }))
    }

    fn http_plan(http: Option<&HttpSpec>) -> Result<Option<HttpPlan>, NetworkError> {
        let Some(http) = http else {
            return Ok(None);
        };

        Ok(Some(HttpPlan {
            protected_ranges: http
                .protected_ranges
                .iter()
                .map(|range| CidrRange::parse(range))
                .collect::<Result<Vec<_>, _>>()?,
        }))
    }
}

impl OutboundRulePlan {
    pub(crate) fn parse(rule: &OutboundRuleSpec) -> Result<Self, NetworkError> {
        match rule {
            OutboundRuleSpec::AcceptTcp { cidr, ports } => Ok(Self::AcceptTcp {
                cidr: CidrRange::parse(cidr)?,
                ports: ports.clone(),
            }),
            OutboundRuleSpec::AcceptUdp { cidr, ports } => Ok(Self::AcceptUdp {
                cidr: CidrRange::parse(cidr)?,
                ports: ports.clone(),
            }),
            OutboundRuleSpec::AcceptPublicInternet { ports } => Ok(Self::AcceptPublicInternet {
                ports: ports.clone(),
            }),
        }
    }
}

impl CidrRange {
    pub(crate) fn parse(value: &str) -> Result<Self, NetworkError> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| NetworkError::new(format!("invalid CIDR range: {value}")))?;
        let _address = address
            .parse::<std::net::IpAddr>()
            .map_err(|_| NetworkError::new(format!("invalid CIDR address: {value}")))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| NetworkError::new(format!("invalid CIDR prefix: {value}")))?;

        let net = value.parse::<ipnet::IpNet>().map_err(|_| {
            let max_prefix = if address.contains(':') { 128 } else { 32 };
            if prefix > max_prefix {
                NetworkError::new(format!("invalid CIDR prefix: {value}"))
            } else {
                NetworkError::new(format!("invalid CIDR range: {value}"))
            }
        })?;
        Ok(Self { net })
    }

    pub(crate) fn contains(&self, address: std::net::IpAddr) -> bool {
        self.net.contains(&address)
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
    use crate::config::{NetworkSpec, OutboundPolicy, OutboundSpec};

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
    fn parses_outbound_rules() {
        let plan = NetworkPlan::from_spec(Some(&NetworkSpec {
            outbound: Some(OutboundSpec {
                policy: OutboundPolicy::Deny,
                rules: vec![
                    OutboundRuleSpec::AcceptTcp {
                        cidr: "127.0.0.1/32".to_string(),
                        ports: vec![80],
                    },
                    OutboundRuleSpec::AcceptUdp {
                        cidr: "10.0.2.0/24".to_string(),
                        ports: vec![53],
                    },
                    OutboundRuleSpec::AcceptPublicInternet { ports: vec![443] },
                ],
            }),
            http: None,
        }))
        .unwrap()
        .unwrap();

        assert_eq!(plan.outbound.unwrap().rules.len(), 3);
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

    #[test]
    fn cidr_contains_uses_network_boundaries() {
        let range = CidrRange::parse("192.168.0.0/24").unwrap();

        assert!(range.contains("192.168.0.1".parse().unwrap()));
        assert!(!range.contains("192.168.1.1".parse().unwrap()));
    }
}
