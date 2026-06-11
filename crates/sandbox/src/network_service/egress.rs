use std::io::{self, ErrorKind};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rama_tls_rustls::client::TlsConnectorData;

use super::{
    DnsResolver, DnsResponse, NetworkConnectionAttempt, NetworkEndpoint, NetworkPolicyAction,
    NetworkPolicyDecision, NetworkPolicyRuntime, NetworkProtocol, decide_dns, decide_transport,
    denied_decision, is_allowed_outbound_tcp, is_allowed_outbound_udp, resolve_dns_with_default,
    resolve_dns_with_upstreams, upstream_socket_addr,
};
use crate::network::OutboundRulePlan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostFlowAttempt {
    pub(super) protocol: NetworkProtocol,
    pub(super) transport: NetworkProtocol,
    pub(super) src: NetworkEndpoint,
    pub(super) dst: NetworkEndpoint,
    pub(super) hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdmittedHostFlow {
    pub(super) attempt: HostFlowAttempt,
    pub(super) action: NetworkPolicyAction,
    pub(super) dns_resolvers: Vec<DnsResolver>,
}

#[derive(Debug, Clone)]
pub(super) struct FlowAdmission {
    outbound_rules: Option<Vec<OutboundRulePlan>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
}

pub(super) trait HostEgress: Send + Sync + std::fmt::Debug {
    fn connect_tcp(&self, flow: &AdmittedHostFlow) -> io::Result<TcpStream>;
    fn connect_tcp_timeout(
        &self,
        flow: &AdmittedHostFlow,
        timeout: Duration,
    ) -> io::Result<TcpStream>;
    fn connect_udp(&self, flow: &AdmittedHostFlow) -> io::Result<UdpSocket>;
    fn resolve_dns(&self, flow: &AdmittedHostFlow, request: &[u8]) -> io::Result<DnsResponse>;
    fn tls_connector_data(&self, flow: &AdmittedHostFlow) -> io::Result<TlsConnectorData>;
}

#[derive(Debug)]
pub(super) struct DirectHostEgress;

impl FlowAdmission {
    pub(super) fn new(
        outbound_rules: Option<Vec<OutboundRulePlan>>,
        policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    ) -> Self {
        Self {
            outbound_rules,
            policy,
        }
    }

    pub(super) fn admit_transport(&self, attempt: HostFlowAttempt) -> Option<AdmittedHostFlow> {
        let decision = decide_transport(
            self.policy.as_deref(),
            self.outbound_rules.as_deref(),
            attempt.protocol,
            attempt.src.clone(),
            attempt.dst.clone(),
            attempt.hostname.clone(),
        );
        self.admit(attempt, decision)
    }

    pub(super) fn admit_dns(&self, attempt: HostFlowAttempt) -> Option<AdmittedHostFlow> {
        if self
            .outbound_rules
            .as_deref()
            .is_some_and(|rules| !match attempt.transport {
                NetworkProtocol::Tcp => {
                    is_allowed_outbound_tcp(&attempt.dst.ip, attempt.dst.port, rules)
                }
                NetworkProtocol::Udp => {
                    is_allowed_outbound_udp(&attempt.dst.ip, attempt.dst.port, rules)
                }
                NetworkProtocol::Dns => true,
            })
        {
            return None;
        }
        let decision = decide_dns(
            self.policy.as_deref(),
            attempt.transport,
            attempt.src.clone(),
            attempt.dst.clone(),
        )
        .unwrap_or_else(|_| denied_decision());
        self.admit(attempt, decision)
    }

    pub(super) fn notify_closed(&self, flow: &AdmittedHostFlow) {
        let Some(policy) = self.policy.as_deref() else {
            return;
        };
        let _ = policy.connection_closed(NetworkConnectionAttempt {
            protocol: flow.attempt.protocol,
            transport: flow.attempt.transport,
            src: flow.attempt.src.clone(),
            dst: flow.attempt.dst.clone(),
            hostname: flow.attempt.hostname.clone(),
        });
    }

    fn admit(
        &self,
        attempt: HostFlowAttempt,
        decision: NetworkPolicyDecision,
    ) -> Option<AdmittedHostFlow> {
        (decision.action != NetworkPolicyAction::Deny).then_some(AdmittedHostFlow {
            attempt,
            action: decision.action,
            dns_resolvers: decision.dns_resolvers,
        })
    }
}

impl HostEgress for DirectHostEgress {
    fn connect_tcp(&self, flow: &AdmittedHostFlow) -> io::Result<TcpStream> {
        TcpStream::connect(upstream_socket_addr(
            &flow.attempt.dst.ip,
            flow.attempt.dst.port,
        ))
    }

    fn connect_tcp_timeout(
        &self,
        flow: &AdmittedHostFlow,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(
            &upstream_resolved_socket_addr(&flow.attempt.dst.ip, flow.attempt.dst.port)?,
            timeout,
        )
    }

    fn connect_udp(&self, flow: &AdmittedHostFlow) -> io::Result<UdpSocket> {
        let destination_ip = flow
            .attempt
            .dst
            .ip
            .parse::<std::net::IpAddr>()
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        let bind_address = if destination_ip.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.connect(std::net::SocketAddr::new(
            destination_ip,
            flow.attempt.dst.port,
        ))?;
        Ok(socket)
    }

    fn resolve_dns(&self, flow: &AdmittedHostFlow, request: &[u8]) -> io::Result<DnsResponse> {
        if flow.dns_resolvers.is_empty() {
            return resolve_dns_with_default(request)
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "unsupported DNS request"));
        }

        let request_message = super::DnsMessage::from_vec(request)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        let packet = resolve_dns_with_upstreams(self, request, flow)
            .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, "DNS upstream did not answer"))?;
        let response_message = super::DnsMessage::from_vec(&packet)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        Ok(DnsResponse {
            packet,
            pins: super::dns_answer_pins(&request_message, &response_message),
        })
    }

    fn tls_connector_data(&self, _flow: &AdmittedHostFlow) -> io::Result<TlsConnectorData> {
        native_root_tls_connector_data()
    }
}

fn upstream_resolved_socket_addr(
    destination_ip: &str,
    destination_port: u16,
) -> io::Result<std::net::SocketAddr> {
    upstream_socket_addr(destination_ip, destination_port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::AddrNotAvailable, "upstream address not found"))
}

fn native_root_tls_connector_data() -> io::Result<TlsConnectorData> {
    static TLS: OnceLock<TlsConnectorData> = OnceLock::new();
    if let Some(tls) = TLS.get() {
        return Ok(tls.clone());
    }
    let tls = build_native_root_tls_connector_data()?;
    let _ = TLS.set(tls.clone());
    Ok(tls)
}

fn build_native_root_tls_connector_data() -> io::Result<TlsConnectorData> {
    let roots = load_native_root_cert_store()?;
    Ok(tls_connector_data_from_roots(roots))
}

pub(super) fn tls_connector_data_from_roots(roots: rustls::RootCertStore) -> TlsConnectorData {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsConnectorData::from(config)
}

fn load_native_root_cert_store() -> io::Result<rustls::RootCertStore> {
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        let error = if result.errors.is_empty() {
            "native TLS root store is empty".to_string()
        } else {
            format!(
                "failed to load native TLS roots: {}",
                result
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        };
        return Err(io::Error::new(ErrorKind::NotFound, error));
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in result.certs {
        roots.add(cert).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("failed to add native TLS root: {error}"),
            )
        })?;
    }
    Ok(roots)
}
