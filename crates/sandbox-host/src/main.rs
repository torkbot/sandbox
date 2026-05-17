use std::env;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use bson::Document;
use sandbox::config::MountSpec;
use sandbox::config::{HttpSpecInput, MicroVmSpecInput, MountSpecInput};
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
        http_handler: spec
            .network
            .as_ref()
            .and_then(|network| network.http.as_ref())
            .map(|_| {
                bridge.clone() as std::sync::Arc<dyn sandbox::network_service::HostHttpHandler>
            }),
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

        while let Ok(packet) = command_rx.try_recv() {
            vm.control_socket_mut().write_packet(&packet)?;
        }

        if let Some(packet) = vm.control_socket_mut().try_read_packet()? {
            bridge.write_raw_packet(&packet)?;
        }

        thread::sleep(Duration::from_millis(10));
    }
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
            MountSpec::VirtualFs { path } => {
                let tag = format!("vfs{index}");
                Some(VirtualFsDevice {
                    tag,
                    path: path.clone(),
                    backend: NodeVirtualFs::new(path.clone(), bridge.clone()),
                })
            }
            MountSpec::SqliteFs { .. } => None,
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
                name: optional_string(document, "name"),
            })
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

    Ok(Some(HttpSpecInput { protected_ranges }))
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
