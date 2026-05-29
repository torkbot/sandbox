use std::env;
use std::io::{self, ErrorKind, Read};
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use bson::{Bson, Document, doc};
use sandbox::block_storage::CowBlockStore;
use sandbox::config::MountSpec;
use sandbox::config::{
    HttpRequestHeaderHookSpec, HttpSpecInput, MicroVmSpecInput, MountSpecInput, NetworkPolicySpec,
    OutboundPolicy, OutboundRuleSpec, OutboundSpec, RootfsStorageSpecInput,
};
use sandbox::http_flow::{
    HookBackedHttpInterceptRuntime, HttpHookExecutor, InterceptedHttpRequest,
};
use sandbox::network_service::{
    NetworkConnectionAttempt, NetworkPolicyAction, NetworkPolicyDecision, NetworkPolicyRuntime,
    NetworkProtocol,
};
use sandbox::runtime::{ControlSocket, HostServices, StartStatusObserver, VirtualFsDevice};

mod host_vfs;

use host_vfs::{HostIoBridge, NodeVirtualFs, StaticFileVirtualFs};

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
    let (bridge_tx, bridge_rx) = mpsc::channel::<Result<(), String>>();
    let guest_writer_slot: Arc<(Mutex<Option<ControlSocket>>, Condvar)> =
        Arc::new((Mutex::new(None), Condvar::new()));
    let start_status_slot: Arc<Mutex<Option<StartStatusObserver>>> = Arc::new(Mutex::new(None));

    let stdin_bridge = bridge.clone();
    let stdin_tx = bridge_tx.clone();
    let stdin_guest_writer = guest_writer_slot.clone();
    let stdin_start_status = start_status_slot.clone();
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            let (packet, document) = match read_packet(&mut stdin) {
                Ok(value) => value,
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                    let start_status = stdin_start_status.lock().unwrap().clone();
                    let result = match start_status.and_then(|status| status.get()) {
                        Some(Ok(())) => Ok(()),
                        Some(Err(error)) => {
                            Err(format!("VM exited after host stdin closed: {error}"))
                        }
                        None => Err("host stdin closed before VM launch completed".to_string()),
                    };
                    let _ = stdin_tx.send(result);
                    return;
                }
                Err(error) => {
                    let _ = stdin_tx.send(Err(format!("read host control packet: {error}")));
                    return;
                }
            };
            if stdin_bridge.route_response(document) {
                continue;
            }

            let (writer_lock, writer_ready) = &*stdin_guest_writer;
            let mut writer = writer_lock.lock().unwrap();
            while writer.is_none() {
                writer = writer_ready.wait(writer).unwrap();
            }
            if let Err(error) = writer.as_mut().unwrap().write_packet(&packet) {
                let _ = stdin_tx.send(Err(format!("write guest control packet: {error}")));
                return;
            }
        }
    });

    let virtual_fs = virtual_fs_devices(&spec, bridge.clone());
    let services = HostServices {
        http: http_intercept_runtime(&spec, bridge.clone())?,
        network_policy: network_policy_runtime(&spec, bridge.clone()),
        root_storage: spec.rootfs.storage.as_ref().map(|storage| {
            Arc::new(NodeCowBlockStore::new(
                bridge.clone(),
                match storage {
                    sandbox::config::RootfsStorageSpec::CowBlockStore { block_size } => *block_size,
                },
            )) as Arc<dyn CowBlockStore>
        }),
    };
    let mut vm = sandbox::runtime::KrunVm::create_with_services(&spec, virtual_fs, services)?;
    vm.start()?;

    {
        let (writer_lock, writer_ready) = &*guest_writer_slot;
        *writer_lock.lock().unwrap() = Some(vm.control_socket().try_clone()?);
        writer_ready.notify_all();
    }
    let mut guest_reader = vm.control_socket().try_clone()?;

    let start_status = vm.start_status_observer();
    *start_status_slot.lock().unwrap() = Some(start_status.clone());
    let status_tx = bridge_tx.clone();
    thread::spawn(move || {
        if let Err(error) = start_status.wait() {
            let _ = status_tx.send(Err(error.to_string()));
        }
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

fn network_policy_runtime(
    spec: &sandbox::MicroVmSpec,
    bridge: Arc<HostIoBridge>,
) -> Option<Arc<dyn NetworkPolicyRuntime>> {
    spec.network
        .as_ref()
        .and_then(|network| network.policy.as_ref())
        .and_then(|policy| policy.connection_hook.then_some(()))
        .map(|()| Arc::new(NodeNetworkPolicyRuntime { bridge }) as Arc<dyn NetworkPolicyRuntime>)
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
        if self.authority == "*" {
            return self.scheme == parts.scheme;
        }
        self.scheme == parts.scheme
            && canonical_authority(parts.scheme, parts.authority)
                .is_ok_and(|authority| authority == self.authority)
    }
}

#[derive(Debug)]
struct NodeHttpHookExecutor {
    bridge: Arc<HostIoBridge>,
    hooks: Vec<NodeRequestHeaderHook>,
}

#[derive(Debug)]
struct NodeNetworkPolicyRuntime {
    bridge: Arc<HostIoBridge>,
}

#[derive(Debug)]
struct NodeCowBlockStore {
    bridge: Arc<HostIoBridge>,
    block_size: u64,
}

impl NodeCowBlockStore {
    fn new(bridge: Arc<HostIoBridge>, block_size: u64) -> Self {
        Self { bridge, block_size }
    }
}

impl CowBlockStore for NodeCowBlockStore {
    fn block_size(&self) -> u64 {
        self.block_size
    }

    fn list_blocks(&self) -> io::Result<std::collections::HashSet<u64>> {
        let response = self.bridge.request(doc! {
            "type": "host.block.list",
        })?;
        let blocks = response
            .get_array("blocks")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        blocks
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "block id must be a string")
                    })?
                    .parse::<u64>()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .collect()
    }

    fn read_blocks(&self, start: u64, count: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
        let response = self.bridge.request(doc! {
            "type": "host.block.read",
            "start": start.to_string(),
            "count": i64::try_from(count).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block count exceeds i64"))?,
        })?;
        let chunks = response
            .get_array("chunks")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        chunks
            .iter()
            .map(|value| {
                let document = value.as_document().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "block chunk must be a document")
                })?;
                let index = document
                    .get_str("start")
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                    .parse::<u64>()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let data = document
                    .get_binary_generic("data")
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                    .to_vec();
                Ok((index, data))
            })
            .collect()
    }

    fn write_blocks(&self, chunks: Vec<(u64, Vec<u8>)>) -> io::Result<()> {
        let chunks = chunks
            .into_iter()
            .map(|(index, data)| {
                Bson::Document(doc! {
                    "start": index.to_string(),
                    "data": Bson::Binary(bson::Binary {
                        subtype: bson::spec::BinarySubtype::Generic,
                        bytes: data,
                    }),
                })
            })
            .collect::<Vec<_>>();
        self.bridge.request(doc! {
            "type": "host.block.write",
            "chunks": chunks,
        })?;
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        self.bridge.request(doc! {
            "type": "host.block.flush",
        })?;
        Ok(())
    }
}

impl NetworkPolicyRuntime for NodeNetworkPolicyRuntime {
    fn decide_connection(
        &self,
        connection: NetworkConnectionAttempt,
    ) -> io::Result<NetworkPolicyDecision> {
        let response = self.bridge.request(doc! {
            "type": "host.network.connection",
            "protocol": match connection.protocol {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
                NetworkProtocol::Dns => "dns",
            },
            "transport": match connection.transport {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
                NetworkProtocol::Dns => "dns",
            },
            "srcIp": connection.src.ip,
            "srcPort": i32::from(connection.src.port),
            "dstIp": connection.dst.ip,
            "dstPort": i32::from(connection.dst.port),
        })?;
        let action = match response.get_str("action").unwrap_or("deny") {
            "accept" => NetworkPolicyAction::Accept,
            "acceptHttp" => NetworkPolicyAction::AcceptHttp,
            "deny" => NetworkPolicyAction::Deny,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported network policy action: {other}"),
                ));
            }
        };
        Ok(NetworkPolicyDecision { action })
    }

    fn connection_closed(&self, connection: NetworkConnectionAttempt) -> io::Result<()> {
        self.bridge.request(doc! {
            "type": "host.network.closed",
            "protocol": match connection.protocol {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
                NetworkProtocol::Dns => "dns",
            },
            "transport": match connection.transport {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
                NetworkProtocol::Dns => "dns",
            },
            "srcIp": connection.src.ip,
            "srcPort": i32::from(connection.src.port),
            "dstIp": connection.dst.ip,
            "dstPort": i32::from(connection.dst.port),
        })?;
        Ok(())
    }
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
            "sourceIp": request.source.ip,
            "sourcePort": i32::from(request.source.port),
            "originalDestinationIp": request.original_destination.ip,
            "originalDestinationPort": i32::from(request.original_destination.port),
            "originalDestinationHostname": request.original_destination.hostname,
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
    let mut devices: Vec<VirtualFsDevice> = spec
        .network
        .as_ref()
        .and_then(|network| network.http.as_ref())
        .and_then(|http| http.ca_certificate_pem.as_ref())
        .map(|certificate| {
            vec![VirtualFsDevice {
                tag: "sandbox-http-ca".to_string(),
                path: "/run/sandbox/http-ca".to_string(),
                readonly: true,
                backend: StaticFileVirtualFs::new("http-ca.pem", certificate.as_bytes().to_vec()),
            }]
        })
        .unwrap_or_default();

    devices.extend(
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
            }),
    );
    devices
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
        rootfs_storage: parse_rootfs_storage(document.get_document("rootfsStorage").ok())?,
        mounts: parse_mounts(document.get_array("mounts")?)?,
        network_outbound: parse_network_outbound(document.get_document("networkOutbound").ok())?,
        network_http: parse_network_http(document.get_document("networkHttp").ok())?,
        network_policy: parse_network_policy(document.get_document("networkPolicy").ok())?,
    })
}

fn parse_network_policy(
    document: Option<&Document>,
) -> Result<Option<NetworkPolicySpec>, Box<dyn std::error::Error>> {
    let Some(document) = document else {
        return Ok(None);
    };
    Ok(Some(NetworkPolicySpec {
        connection_hook: document.get_bool("connectionHook")?,
    }))
}

fn parse_rootfs_storage(
    document: Option<&Document>,
) -> Result<Option<RootfsStorageSpecInput>, Box<dyn std::error::Error>> {
    let Some(document) = document else {
        return Ok(None);
    };
    Ok(Some(RootfsStorageSpecInput {
        kind: document.get_str("kind")?.to_string(),
        block_size: u64::try_from(document.get_i32("blockSize")?)?,
    }))
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
