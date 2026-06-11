use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use hickory_proto::op::{Message as DnsMessage, MessageType as DnsMessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::egress::{AdmittedHostFlow, HostEgress, HostFlowAttempt};
use super::{DnsResolver, NetworkEndpoint, NetworkProtocol};

pub(super) const DNS_PACKET_BUFFER_BYTES: usize = 4096;
pub(super) const DNS_DEFAULT_TTL_SECS: u32 = 60;
pub(super) const DNS_UPSTREAM_ATTEMPTS: usize = 3;
const DNS_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub(super) struct DnsResponse {
    pub(super) packet: Vec<u8>,
    pub(super) pins: Vec<DnsAnswerPin>,
}

impl DnsResponse {
    pub(super) fn answer_pins(&self) -> impl Iterator<Item = &DnsAnswerPin> {
        self.pins.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DnsAnswerPin {
    pub(super) hostname: String,
    pub(super) address: [u8; 4],
    pub(super) ttl: Duration,
}

pub(super) fn resolve_dns_with_default(request: &[u8]) -> Option<DnsResponse> {
    let request_message = DnsMessage::from_vec(request).ok()?;
    let query = single_dns_query(&request_message)?;
    let name = dns_name_string(query.name());
    let supported_question =
        query.query_class() == DNSClass::IN && query.query_type() == RecordType::A;
    let answer = if supported_question {
        dns_address(&name)
    } else {
        None
    };
    let name_exists = if supported_question {
        answer.is_some()
    } else {
        dns_address(&name).is_some()
    };

    let mut response_message = DnsMessage::new(
        request_message.metadata.id,
        DnsMessageType::Response,
        request_message.metadata.op_code,
    );
    response_message.metadata =
        hickory_proto::op::Metadata::response_from_request(&request_message.metadata);
    response_message.metadata.recursion_available = true;
    if !name_exists {
        response_message.metadata.response_code = ResponseCode::NXDomain;
    }
    response_message.add_query(query.clone());

    if let Some(address) = answer {
        response_message.add_answer(Record::from_rdata(
            query.name().clone(),
            DNS_DEFAULT_TTL_SECS,
            RData::A(A(Ipv4Addr::from(address))),
        ));
    }

    let packet = response_message.to_vec().ok()?;
    Some(DnsResponse {
        packet,
        pins: dns_answer_pins(&request_message, &response_message),
    })
}

pub(super) fn resolve_dns_with_upstreams(
    egress: &dyn HostEgress,
    request: &[u8],
    flow: &AdmittedHostFlow,
) -> Option<Vec<u8>> {
    for _ in 0..DNS_UPSTREAM_ATTEMPTS {
        for resolver in &flow.dns_resolvers {
            let response = match flow.attempt.transport {
                NetworkProtocol::Udp => {
                    resolve_dns_with_udp_upstream(egress, request, flow, resolver)
                        .or_else(|| resolve_dns_with_tcp_upstream(egress, request, flow, resolver))
                }
                NetworkProtocol::Tcp => {
                    resolve_dns_with_tcp_upstream(egress, request, flow, resolver)
                        .or_else(|| resolve_dns_with_udp_upstream(egress, request, flow, resolver))
                }
                NetworkProtocol::Dns => None,
            };
            if response.is_some() {
                return response;
            }
        }
    }
    None
}

fn dns_upstream_flow(
    base: &AdmittedHostFlow,
    transport: NetworkProtocol,
    resolver: &DnsResolver,
) -> AdmittedHostFlow {
    AdmittedHostFlow {
        attempt: HostFlowAttempt {
            protocol: NetworkProtocol::Dns,
            transport,
            src: base.attempt.src.clone(),
            dst: NetworkEndpoint {
                ip: resolver.ip.clone(),
                port: resolver.port,
            },
            hostname: None,
        },
        action: base.action,
        dns_resolvers: Vec::new(),
    }
}

fn resolve_dns_with_udp_upstream(
    egress: &dyn HostEgress,
    request: &[u8],
    flow: &AdmittedHostFlow,
    resolver: &DnsResolver,
) -> Option<Vec<u8>> {
    let resolver_flow = dns_upstream_flow(flow, NetworkProtocol::Udp, resolver);
    let Ok(socket) = egress.connect_udp(&resolver_flow) else {
        return None;
    };
    let _ = socket.set_read_timeout(Some(DNS_UPSTREAM_TIMEOUT));
    let _ = socket.set_write_timeout(Some(DNS_UPSTREAM_TIMEOUT));
    if socket.send(request).is_err() {
        return None;
    }
    let mut response = vec![0; DNS_PACKET_BUFFER_BYTES];
    let Ok(received) = socket.recv(&mut response) else {
        return None;
    };
    response.truncate(received);
    Some(response)
}

fn resolve_dns_with_tcp_upstream(
    egress: &dyn HostEgress,
    request: &[u8],
    flow: &AdmittedHostFlow,
    resolver: &DnsResolver,
) -> Option<Vec<u8>> {
    let resolver_flow = dns_upstream_flow(flow, NetworkProtocol::Tcp, resolver);
    let Ok(mut stream) = egress.connect_tcp_timeout(&resolver_flow, DNS_UPSTREAM_TIMEOUT) else {
        return None;
    };
    let _ = stream.set_read_timeout(Some(DNS_UPSTREAM_TIMEOUT));
    let _ = stream.set_write_timeout(Some(DNS_UPSTREAM_TIMEOUT));
    let request_len = u16::try_from(request.len()).ok()?;
    if stream.write_all(&request_len.to_be_bytes()).is_err() {
        return None;
    }
    if stream.write_all(request).is_err() {
        return None;
    }
    let mut response_len = [0; 2];
    if stream.read_exact(&mut response_len).is_err() {
        return None;
    }
    let response_len = u16::from_be_bytes(response_len) as usize;
    if response_len > DNS_PACKET_BUFFER_BYTES {
        return None;
    }
    let mut response = vec![0; response_len];
    if stream.read_exact(&mut response).is_err() {
        return None;
    }
    Some(response)
}

pub(super) fn single_dns_query(message: &DnsMessage) -> Option<&hickory_proto::op::Query> {
    match message.queries.as_slice() {
        [query] => Some(query),
        _ => None,
    }
}

pub(super) fn dns_answer_pins(request: &DnsMessage, response: &DnsMessage) -> Vec<DnsAnswerPin> {
    let Some(query) = single_dns_query(request) else {
        return Vec::new();
    };
    let name = dns_name_string(query.name());
    let answer_names = dns_answer_names_for_query(query.name(), response);
    response
        .answers
        .iter()
        .chain(response.additionals.iter())
        .filter_map(|record| match &record.data {
            RData::A(address)
                if record.dns_class == DNSClass::IN && answer_names.contains(&record.name) =>
            {
                Some(DnsAnswerPin {
                    hostname: name.clone(),
                    address: address.0.octets(),
                    ttl: Duration::from_secs(record.ttl.into()),
                })
            }
            _ => None,
        })
        .collect()
}

fn dns_answer_names_for_query(query_name: &Name, response: &DnsMessage) -> HashSet<Name> {
    let mut names = HashSet::from([query_name.clone()]);
    for _ in 0..8 {
        let mut changed = false;
        for record in &response.answers {
            let RData::CNAME(target) = &record.data else {
                continue;
            };
            if record.dns_class == DNSClass::IN
                && names.contains(&record.name)
                && names.insert((**target).clone())
            {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    names
}

fn dns_name_string(name: &hickory_proto::rr::Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

fn dns_address(name: &str) -> Option<[u8; 4]> {
    (name, 0)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(address) => Some(address.octets()),
            std::net::IpAddr::V6(_) => None,
        })
}
