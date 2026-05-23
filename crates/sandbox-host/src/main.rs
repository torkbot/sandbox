use std::env;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use bson::{Bson, Document, doc};
use sandbox::config::MountSpec;
use sandbox::config::{
    HttpRequestHeaderHookSpec, HttpSpecInput, MicroVmSpecInput, MountSpecInput, OutboundPolicy,
    OutboundRuleSpec, OutboundSpec,
};
use sandbox::http_flow::{
    HookBackedHttpInterceptRuntime, HttpHookExecutor, InterceptedHttpRequest,
};
use sandbox::runtime::{HostServices, VirtualFsDevice};

mod host_vfs;

use host_vfs::{HostIoBridge, NodeVirtualFs};

const USAGE: &str = "usage: sandbox-host --capabilities | --stdio";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("--capabilities"), None) => {
            print_capabilities();
            ExitCode::SUCCESS
        }
        (Some("--stdio"), None) => run_stdio(),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn print_capabilities() {
    println!(concat!(
        "{{",
        "\"schemaVersion\":1,",
        "\"vmHost\":true,",
        "\"controlTransport\":\"unix-fd\",",
        "\"hypervisorEntitlementProcess\":true",
        "}}"
    ));
}

fn run_stdio() -> ExitCode {
    match run_stdio_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sandbox-host: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_stdio_inner() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = io::stdin().lock();
    let spawn_document = read_document_packet(&mut stdin)?;
    drop(stdin);

    let spec = sandbox::MicroVmSpec::build(parse_spawn(spawn_document)?)?;
    let bridge = HostIoBridge::new();
    let virtual_fs = virtual_fs_devices(&spec, bridge.clone());
    let services = HostServices {
        http: http_intercept_runtime(&spec, bridge.clone())?,
    };
    let mut vm = sandbox::runtime::KrunVm::create_with_services(&spec, virtual_fs, services)?;
    vm.start()?;

    let mut guest_writer = vm.control_socket().try_clone()?;
    let mut guest_reader = vm.control_socket().try_clone()?;
    let (bridge_tx, bridge_rx) = mpsc::channel::<Result<(), String>>();

    let start_status = vm.start_status_observer();
    let status_tx = bridge_tx.clone();
    thread::spawn(move || {
        if let Err(error) = start_status.wait() {
            let _ = status_tx.send(Err(error.to_string()));
        }
    });

    let stdin_bridge = bridge.clone();
    let stdin_tx = bridge_tx.clone();
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        while let Ok((packet, document)) = read_packet(&mut stdin) {
            if stdin_bridge.route_response(document) {
                continue;
            }
            if let Err(error) = guest_writer.write_packet(&packet) {
                let _ = stdin_tx.send(Err(format!("write guest control packet: {error}")));
                return;
            }
        }
        let _ = stdin_tx.send(Ok(()));
    });

    let guest_tx = bridge_tx.clone();
    thread::spawn(move || {
        loop {
            let packet = match guest_reader.read_packet() {
                Ok(packet) => packet,
                Err(error) => {
                    let _ = guest_tx.send(Err(format!("read guest control packet: {error}")));
                    return;
                }
            };
            if let Err(error) = bridge.write_raw_packet(&packet) {
                let _ = guest_tx.send(Err(format!("write host control packet: {error}")));
                return;
            }
        }
    });

    match bridge_rx.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            if let Some(result) = vm.start_status() {
                result?;
            }
            Err(error.into())
        }
        Err(error) => Err(format!("control bridge stopped: {error}").into()),
    }
}

fn http_intercept_runtime(
    spec: &sandbox::MicroVmSpec,
    bridge: Arc<HostIoBridge>,
) -> Result<Option<Arc<dyn sandbox::http_flow::HttpInterceptRuntime>>, Box<dyn std::error::Error>> {
    let Some(http) = spec
        .network
        .as_ref()
        .and_then(|network| network.http.as_ref())
    else {
        return Ok(None);
    };
    let hooks = http
        .request_header_hooks
        .iter()
        .map(|hook| {
            Ok(NodeRequestHeaderHook {
                id: hook.id.clone(),
                selector: RequestHookSelector::parse(&hook.origin)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Some(Arc::new(HookBackedHttpInterceptRuntime::new(
        NodeHttpHookExecutor { bridge, hooks },
    ))))
}

#[derive(Debug, Clone)]
struct RequestHookSelector {
    scheme: String,
    authority: String,
}

impl RequestHookSelector {
    fn parse(origin: &str) -> Result<Self, String> {
        let (scheme, rest) = origin
            .split_once("://")
            .ok_or_else(|| "HTTP request selector origin must include a scheme".to_string())?;
        if scheme != "http" && scheme != "https" {
            return Err("HTTP request selector origin scheme must be http or https".to_string());
        }
        let authority = rest.trim_end_matches('/');
        if authority.is_empty() || authority.contains('/') {
            return Err(
                "HTTP request selector origin must be an origin, not a URL path".to_string(),
            );
        }
        Ok(Self {
            scheme: scheme.to_string(),
            authority: canonical_authority(scheme, authority)?,
        })
    }

    fn matches(&self, url: &str) -> bool {
        let Ok(parts) = request_url_origin(url) else {
            return false;
        };
        self.scheme == parts.scheme
            && canonical_authority(parts.scheme, parts.authority)
                .is_ok_and(|authority| authority == self.authority)
    }

    fn matches_rebound_authority(&self, scheme: &str, authority: &str) -> bool {
        self.scheme == scheme
            && canonical_authority(scheme, authority)
                .is_ok_and(|authority| authority == self.authority)
            && is_hostname(&self.authority)
    }
}

#[derive(Debug)]
struct NodeHttpHookExecutor {
    bridge: Arc<HostIoBridge>,
    hooks: Vec<NodeRequestHeaderHook>,
}

#[derive(Debug)]
struct NodeRequestHeaderHook {
    id: String,
    selector: RequestHookSelector,
}

impl HttpHookExecutor for NodeHttpHookExecutor {
    fn apply_request_headers(
        &self,
        request: InterceptedHttpRequest,
    ) -> io::Result<Vec<(String, String)>> {
        let matching_hook_ids = self
            .hooks
            .iter()
            .filter(|hook| hook.selector.matches(&request.url))
            .map(|hook| hook.id.clone())
            .collect();
        let hook_ids = self.active_hook_ids(matching_hook_ids)?;
        if hook_ids.is_empty() {
            return Ok(request.headers);
        }

        let response = self.bridge.request(doc! {
            "type": "host.http.requestHeaders",
            "hookIds": hook_ids,
            "protocol": match request.protocol {
                sandbox::http_interception::HttpRequestProtocol::Http1 => "http/1.1",
                sandbox::http_interception::HttpRequestProtocol::Http2 => "h2",
            },
            "method": request.method,
            "url": request.url,
            "originalDestinationIp": request.original_destination.ip,
            "originalDestinationPort": i32::from(request.original_destination.port),
            "upstreamDialIp": request.upstream_dial.ip,
            "upstreamDialPort": i32::from(request.upstream_dial.port),
            "headers": request.headers.into_iter().map(|(name, value)| {
                Bson::Array(vec![Bson::String(name), Bson::String(value)])
            }).collect::<Vec<_>>(),
            "tls": request.tls.map(|tls| doc! {
                "sni": tls.server_name,
                "alpn": tls.alpn_protocol,
            }),
        })?;
        response_header_pairs(&response)
    }

    fn rejects_rebound_authority(
        &self,
        scheme: &str,
        authority: &str,
        original_destination: &sandbox::http_flow::InterceptedDestination,
        upstream_dial: &sandbox::http_flow::InterceptedDestination,
    ) -> bool {
        let candidate_hook_ids = self
            .hooks
            .iter()
            .filter(|hook| hook.selector.matches_rebound_authority(scheme, authority))
            .map(|hook| hook.id.clone())
            .collect::<Vec<_>>();
        if candidate_hook_ids.is_empty()
            || !is_rebound_authority(authority, original_destination, upstream_dial)
        {
            return false;
        }
        match self.active_hook_ids(candidate_hook_ids) {
            Ok(active_hook_ids) => !active_hook_ids.is_empty(),
            Err(_) => true,
        }
    }
}

impl NodeHttpHookExecutor {
    fn active_hook_ids(&self, hook_ids: Vec<String>) -> io::Result<Vec<String>> {
        if hook_ids.is_empty() {
            return Ok(Vec::new());
        }
        let response = self.bridge.request(doc! {
            "type": "host.http.activeRequestHeaderHooks",
            "hookIds": hook_ids,
        })?;
        response
            .get_array("hookIds")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "hook id must be a string")
                })
            })
            .collect()
    }
}

fn is_rebound_authority(
    authority: &str,
    original_destination: &sandbox::http_flow::InterceptedDestination,
    upstream_dial: &sandbox::http_flow::InterceptedDestination,
) -> bool {
    let Some(host) = authority_host(authority) else {
        return false;
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    original_destination.ip != upstream_dial.ip
        && (is_special_use_ip(&original_destination.ip) || is_special_use_ip(&upstream_dial.ip))
}

struct RequestUrlOrigin<'a> {
    scheme: &'a str,
    authority: &'a str,
}

fn request_url_origin(url: &str) -> io::Result<RequestUrlOrigin<'_>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request URL missing scheme"))?;
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _)| authority);
    Ok(RequestUrlOrigin { scheme, authority })
}

fn canonical_authority(scheme: &str, authority: &str) -> Result<String, String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("HTTP request selector authority must not be empty".to_string());
    }
    let (host, port) = split_authority(authority);
    let host = host.to_ascii_lowercase();
    match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => Ok(host),
        (_, Some(port)) => Ok(format!("{host}:{port}")),
    }
}

fn is_hostname(authority: &str) -> bool {
    authority_host(authority)
        .map(|host| host.parse::<std::net::IpAddr>().is_err())
        .unwrap_or(false)
}

fn authority_host(authority: &str) -> Option<&str> {
    let without_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = without_userinfo.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }
    Some(
        without_userinfo
            .split_once(':')
            .map_or(without_userinfo, |(host, _)| host),
    )
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

fn is_special_use_ip(value: &str) -> bool {
    match value.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
                || octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
                || octets[0] == 192 && octets[1] == 0 && octets[2] == 0
                || octets[0] == 192 && octets[1] == 88 && octets[2] == 99
                || octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
                || octets[0] >= 240
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
        Err(_) => true,
    }
}

fn response_header_pairs(document: &Document) -> io::Result<Vec<(String, String)>> {
    document
        .get_array("headers")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        .iter()
        .map(|value| {
            let values = value.as_array().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "header entry must be an array")
            })?;
            let name = values.first().and_then(Bson::as_str).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "header name must be a string")
            })?;
            let header_value = values.get(1).and_then(Bson::as_str).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "header value must be a string")
            })?;
            Ok((name.to_string(), header_value.to_string()))
        })
        .collect()
}

fn read_document_packet(reader: &mut impl Read) -> Result<Document, Box<dyn std::error::Error>> {
    let (_packet, document) = read_packet(reader)?;
    Ok(document)
}

fn read_packet(reader: &mut impl Read) -> io::Result<(Vec<u8>, Document)> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let frame_len = u32::from_le_bytes(len) as usize;
    let mut packet = Vec::with_capacity(4 + frame_len);
    packet.extend_from_slice(&len);
    packet.resize(4 + frame_len, 0);
    reader.read_exact(&mut packet[4..])?;
    let document = Document::from_reader(&packet[4..])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    Ok((packet, document))
}

fn virtual_fs_devices(
    spec: &sandbox::MicroVmSpec,
    bridge: std::sync::Arc<HostIoBridge>,
) -> Vec<VirtualFsDevice> {
    spec.mounts
        .iter()
        .enumerate()
        .filter_map(|(index, mount)| match mount {
            MountSpec::VirtualFs { path, writable } => {
                let tag = format!("vfs{index}");
                Some(VirtualFsDevice {
                    tag,
                    path: path.clone(),
                    readonly: !writable,
                    backend: NodeVirtualFs::new(path.clone(), bridge.clone()),
                })
            }
        })
        .collect()
}

fn parse_spawn(document: Document) -> Result<MicroVmSpecInput, Box<dyn std::error::Error>> {
    let frame_type = document.get_str("type")?;
    if frame_type != "host.spawn" {
        return Err(format!("expected host.spawn, got {frame_type}").into());
    }

    Ok(MicroVmSpecInput {
        name: optional_string(&document, "name"),
        vcpus: optional_i32(&document, "vcpus")
            .map(u32::try_from)
            .transpose()?,
        memory_mib: optional_i32(&document, "memoryMib")
            .map(u32::try_from)
            .transpose()?,
        kernel_format: optional_string(&document, "kernelFormat"),
        init_crate: document.get_str("initCrate")?.to_string(),
        rootfs_path: document.get_str("rootfsPath")?.to_string(),
        rootfs_readonly: optional_bool(&document, "rootfsReadonly"),
        rootfs_format: document.get_str("rootfsFormat")?.to_string(),
        rootfs_overlay_mode: optional_string(&document, "rootfsOverlayMode"),
        mounts: parse_mounts(document.get_array("mounts")?)?,
        network_outbound: parse_network_outbound(document.get_document("networkOutbound").ok())?,
        network_http: parse_network_http(document.get_document("networkHttp").ok())?,
    })
}

fn parse_mounts(values: &[bson::Bson]) -> Result<Vec<MountSpecInput>, Box<dyn std::error::Error>> {
    values
        .iter()
        .map(|value| {
            let document = value.as_document().ok_or("mount must be a document")?;
            Ok(MountSpecInput {
                kind: document.get_str("kind")?.to_string(),
                path: document.get_str("path")?.to_string(),
                writable: optional_bool(document, "writable"),
            })
        })
        .collect()
}

fn parse_network_outbound(
    document: Option<&Document>,
) -> Result<Option<OutboundSpec>, Box<dyn std::error::Error>> {
    let Some(document) = document else {
        return Ok(None);
    };
    let policy = match document.get_str("policy")? {
        "deny" => OutboundPolicy::Deny,
        other => return Err(format!("unsupported networkOutbound.policy: {other}").into()),
    };
    let rules = document
        .get_array("rules")?
        .iter()
        .map(|value| {
            let document = value
                .as_document()
                .ok_or("network outbound rule must be a document")?;
            if document.get_str("action")? != "accept" {
                return Err("network outbound rule action must be accept".into());
            }
            let ports = parse_ports(document)?;
            if document.get_str("scope").ok() == Some("public-internet") {
                return Ok(OutboundRuleSpec::AcceptPublicInternet { ports });
            }
            let cidr = document.get_str("cidr")?.to_string();
            match document.get_str("protocol")? {
                "tcp" => Ok(OutboundRuleSpec::AcceptTcp { cidr, ports }),
                "udp" => Ok(OutboundRuleSpec::AcceptUdp { cidr, ports }),
                other => Err(format!("unsupported network outbound protocol: {other}").into()),
            }
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    Ok(Some(OutboundSpec { policy, rules }))
}

fn parse_ports(document: &Document) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let Some(values) = document.get_array("ports").ok() else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .map(|value| {
            let port = value
                .as_i32()
                .ok_or("network outbound port must be an integer")?;
            let port = u16::try_from(port)?;
            if port == 0 {
                return Err("network outbound port must be greater than zero".into());
            }
            Ok(port)
        })
        .collect()
}

fn parse_network_http(
    document: Option<&Document>,
) -> Result<Option<HttpSpecInput>, Box<dyn std::error::Error>> {
    let Some(document) = document else {
        return Ok(None);
    };
    let protected_ranges = document
        .get_array("protectedRanges")
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or("protectedRanges entries must be strings")
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_else(|_| Ok(Vec::new()))?;

    Ok(Some(HttpSpecInput {
        protected_ranges,
        ca_certificate_pem: optional_string(document, "caCertificatePem"),
        ca_private_key_pem: optional_string(document, "caPrivateKeyPem"),
        request_header_hooks: parse_request_header_hooks(
            document.get_array("requestHeaderHooks").ok(),
        )?,
    }))
}

fn parse_request_header_hooks(
    values: Option<&Vec<bson::Bson>>,
) -> Result<Vec<HttpRequestHeaderHookSpec>, Box<dyn std::error::Error>> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .map(|value| {
            let document = value
                .as_document()
                .ok_or("requestHeaderHooks entries must be documents")?;
            Ok(HttpRequestHeaderHookSpec {
                id: document.get_str("id")?.to_string(),
                origin: document.get_str("origin")?.to_string(),
            })
        })
        .collect()
}

fn optional_string(document: &Document, key: &str) -> Option<String> {
    document.get_str(key).ok().map(str::to_string)
}

fn optional_i32(document: &Document, key: &str) -> Option<i32> {
    document.get_i32(key).ok()
}

fn optional_bool(document: &Document, key: &str) -> Option<bool> {
    document.get_bool(key).ok()
}
