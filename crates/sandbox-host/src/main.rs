use std::env;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

use bson::{Bson, Document, doc};
use sandbox::config::MountSpec;
use sandbox::config::{
    HttpRequestHeaderHookSpec, HttpSpecInput, MicroVmSpecInput, MountSpecInput, OutboundPolicy,
    OutboundRuleSpec, OutboundSpec,
};
use sandbox::http_flow::{
    HookBackedHttpInterceptRuntime, HttpHookExecutor, InterceptedHttpRequest,
};
use sandbox::http_interception::{
    RequestHeaderHookDecision, RequestHeaderHookRule, RequestHeaderMatch,
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

    let (command_tx, command_rx) = mpsc::channel::<Vec<u8>>();
    let stdin_bridge = bridge.clone();
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        while let Ok((packet, document)) = read_packet(&mut stdin) {
            if stdin_bridge.route_response(document) {
                continue;
            }
            if command_tx.send(packet).is_err() {
                break;
            }
        }
    });

    loop {
        if let Some(result) = vm.start_status() {
            result?;
        }

        loop {
            match command_rx.try_recv() {
                Ok(packet) => vm.control_socket_mut().write_packet(&packet)?,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        if let Some(packet) = vm.control_socket_mut().try_read_packet()? {
            bridge.write_raw_packet(&packet)?;
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn http_intercept_runtime(
    spec: &sandbox::MicroVmSpec,
    bridge: Arc<HostIoBridge>,
) -> Result<Option<Arc<dyn sandbox::http_flow::HttpInterceptRuntime>>, Box<dyn std::error::Error>> {
    let Some(http) = spec.network.as_ref().and_then(|network| network.http.as_ref()) else {
        return Ok(None);
    };
    if http.request_header_hooks.is_empty() {
        return Ok(None);
    }
    let hooks = http
        .request_header_hooks
        .iter()
        .map(|hook| {
            Ok(NodeRequestHeaderHook {
                id: hook.id.clone(),
                rule: RequestHeaderHookRule::parse(&hook.pattern)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Some(Arc::new(HookBackedHttpInterceptRuntime::new(
        NodeHttpHookExecutor { bridge, hooks },
    ))))
}

#[derive(Debug)]
struct NodeHttpHookExecutor {
    bridge: Arc<HostIoBridge>,
    hooks: Vec<NodeRequestHeaderHook>,
}

#[derive(Debug)]
struct NodeRequestHeaderHook {
    id: String,
    rule: RequestHeaderHookRule,
}

impl HttpHookExecutor for NodeHttpHookExecutor {
    fn apply_request_headers(
        &self,
        request: InterceptedHttpRequest,
    ) -> io::Result<Vec<(String, String)>> {
        let parts = request_url_parts(&request.url)?;
        let mut hook_ids = Vec::new();
        for hook in &self.hooks {
            match hook.rule.evaluate(&RequestHeaderMatch {
                protocol: request.protocol,
                scheme: parts.scheme,
                authority: parts.authority,
                path: parts.path,
                original_destination_ip: &request.original_destination.ip,
                upstream_dial_ip: &request.upstream_dial.ip,
            }) {
                RequestHeaderHookDecision::Apply => hook_ids.push(hook.id.clone()),
                RequestHeaderHookDecision::RejectReboundDestination => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "request-header hook rejected rebound destination",
                    ));
                }
                RequestHeaderHookDecision::Ignore => {}
            }
        }
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
}

struct RequestUrlParts<'a> {
    scheme: &'a str,
    authority: &'a str,
    path: &'a str,
}

fn request_url_parts(url: &str) -> io::Result<RequestUrlParts<'_>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request URL missing scheme"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    Ok(RequestUrlParts {
        scheme,
        authority,
        path: if path.is_empty() { "/" } else { &url[url.len() - path.len() - 1..] },
    })
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
                pattern: document.get_str("pattern")?.to_string(),
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
