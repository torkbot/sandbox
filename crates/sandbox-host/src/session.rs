use std::io::{self, ErrorKind};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use bson::{Document, doc};
use sandbox::block_storage::CowBlockStore;
use sandbox::runtime::{BlockDeviceService, KrunVm};

use crate::blob_block::{BlobBlockConfig, BlobBlockFailure, BlobBlockVolume};
use crate::host_vfs::HostIoBridge;

const BLOB_BLOCK_FAILURE_EXIT_GRACE: Duration = Duration::from_secs(5);

pub struct BlobResources {
    bridge: Arc<HostIoBridge>,
    root: Option<BlobBlockVolume>,
    block: Option<BlobBlockVolume>,
}

impl BlobResources {
    fn acquire(
        config: &BlobBlockConfig,
        spawn_document: &Document,
        bridge: Arc<HostIoBridge>,
    ) -> Result<Self, BlobBlockFailure> {
        let resources = spawn_document.get_document("blobResources").ok();
        let root = resources
            .and_then(|resources| resources.get_document("rootOverlay").ok())
            .cloned()
            .map(|document| BlobBlockVolume::acquire(config, document))
            .transpose()?;
        let block = match resources
            .and_then(|resources| resources.get_document("blockDevice").ok())
            .cloned()
            .map(|document| BlobBlockVolume::acquire(config, document))
            .transpose()
        {
            Ok(block) => block,
            Err(error) => {
                let mut root = root;
                if let Some(Err(close_failure)) = root.as_mut().map(BlobBlockVolume::close) {
                    return Err(close_failure);
                }
                return Err(error);
            }
        };
        Ok(Self {
            bridge,
            root,
            block,
        })
    }

    pub fn root_store(&mut self) -> Result<Option<Arc<dyn CowBlockStore>>, BlobBlockFailure> {
        let result = self
            .root
            .as_mut()
            .map(BlobBlockVolume::cow_store)
            .transpose();
        if let Err(failure) = &result {
            report_blob_failure(&self.bridge, failure);
        }
        result
    }

    pub fn block_service(&mut self) -> Result<Option<BlockDeviceService>, BlobBlockFailure> {
        let result = self
            .block
            .as_mut()
            .map(BlobBlockVolume::service)
            .transpose();
        if let Err(failure) = &result {
            report_blob_failure(&self.bridge, failure);
        }
        result
    }

    fn take_failure_receivers(&mut self) -> Vec<mpsc::Receiver<BlobBlockFailure>> {
        [&mut self.root, &mut self.block]
            .into_iter()
            .filter_map(|volume| volume.as_mut()?.take_failure_receiver())
            .collect()
    }

    fn close(&mut self) -> Result<(), BlobBlockFailure> {
        let root = self.root.as_mut().map(BlobBlockVolume::close);
        let block = self.block.as_mut().map(BlobBlockVolume::close);
        root.into_iter()
            .chain(block)
            .find_map(Result::err)
            .map_or(Ok(()), Err)
    }
}

pub fn with_blob_resources<T>(
    config: &BlobBlockConfig,
    spawn_document: &Document,
    bridge: Arc<HostIoBridge>,
    operation: impl FnOnce(&mut BlobResources) -> Result<T, Box<dyn std::error::Error>>,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut resources =
        BlobResources::acquire(config, spawn_document, bridge.clone()).map_err(|failure| {
            report_blob_failure(&bridge, &failure);
            Box::new(failure) as Box<dyn std::error::Error>
        })?;
    let result = operation(&mut resources);
    let close_result = resources.close();
    if let Err(failure) = &close_result {
        report_blob_failure(&bridge, failure);
    }
    let value = result?;
    close_result.map_err(|failure| Box::new(failure) as Box<dyn std::error::Error>)?;
    Ok(value)
}

enum SessionEvent {
    HostPacket(Vec<u8>),
    HostClosed,
    Failed(String),
    GuestPacket(Vec<u8>),
    VmExited(Result<(), sandbox::runtime::KrunError>),
    BlobFailed(BlobBlockFailure),
}

pub struct StdioSession {
    bridge: Arc<HostIoBridge>,
    events: mpsc::Receiver<SessionEvent>,
    event_tx: mpsc::Sender<SessionEvent>,
}

impl StdioSession {
    pub fn begin(bridge: Arc<HostIoBridge>, resources: &mut BlobResources) -> Self {
        let (event_tx, events) = mpsc::channel();
        start_host_input(bridge.clone(), event_tx.clone());
        for failures in resources.take_failure_receivers() {
            monitor_blob_failure(failures, bridge.clone(), event_tx.clone());
        }
        Self {
            bridge,
            events,
            event_tx,
        }
    }

    pub fn run(self, vm: &KrunVm) -> Result<(), Box<dyn std::error::Error>> {
        let mut guest_writer = vm.control_socket().try_clone()?;
        let guest_reader = vm.control_socket().try_clone()?;
        start_guest_output(guest_reader, self.event_tx.clone());
        start_vm_status(vm, self.event_tx.clone());

        let mut launch_ready = false;
        loop {
            match self.events.recv() {
                Ok(SessionEvent::HostPacket(packet)) => guest_writer
                    .write_packet(&packet)
                    .map_err(|error| format!("write guest control packet: {error}"))?,
                Ok(SessionEvent::HostClosed) => {
                    return host_closed_result(
                        vm.start_status()
                            .map(|result| result.map_err(|error| error.to_string())),
                        launch_ready,
                    )
                    .map_err(Into::into);
                }
                Ok(SessionEvent::GuestPacket(packet)) => {
                    if is_init_ready_packet(&packet) {
                        launch_ready = true;
                    }
                    self.bridge
                        .write_raw_packet(&packet)
                        .map_err(|error| format!("write host control packet: {error}"))?;
                }
                Ok(SessionEvent::VmExited(result)) => {
                    return vm_exited_result(
                        result.map_err(|error| error.to_string()),
                        launch_ready,
                    )
                    .map_err(Into::into);
                }
                Ok(SessionEvent::BlobFailed(failure)) => return Err(Box::new(failure)),
                Ok(SessionEvent::Failed(error)) => {
                    if let Some(result) = vm.start_status() {
                        result?;
                    }
                    return Err(error.into());
                }
                Err(error) => return Err(format!("control bridge stopped: {error}").into()),
            }
        }
    }
}

fn start_host_input(bridge: Arc<HostIoBridge>, events: mpsc::Sender<SessionEvent>) {
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            let (packet, document) = match crate::read_packet(&mut stdin) {
                Ok(value) => value,
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                    let _ = events.send(SessionEvent::HostClosed);
                    return;
                }
                Err(error) => {
                    let _ = events.send(SessionEvent::Failed(format!(
                        "read host control packet: {error}"
                    )));
                    return;
                }
            };
            if !bridge.route_response(document)
                && events.send(SessionEvent::HostPacket(packet)).is_err()
            {
                return;
            }
        }
    });
}

fn start_guest_output(
    mut guest_reader: sandbox::runtime::ControlSocket,
    events: mpsc::Sender<SessionEvent>,
) {
    thread::spawn(move || {
        loop {
            match guest_reader.read_packet() {
                Ok(packet) => {
                    if events.send(SessionEvent::GuestPacket(packet)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = events.send(SessionEvent::Failed(format!(
                        "read guest control packet: {error}"
                    )));
                    return;
                }
            }
        }
    });
}

fn start_vm_status(vm: &KrunVm, events: mpsc::Sender<SessionEvent>) {
    let status = vm.start_status_observer();
    thread::spawn(move || {
        let _ = events.send(SessionEvent::VmExited(status.wait()));
    });
}

fn monitor_blob_failure(
    failures: mpsc::Receiver<BlobBlockFailure>,
    bridge: Arc<HostIoBridge>,
    events: mpsc::Sender<SessionEvent>,
) {
    thread::spawn(move || {
        let Ok(failure) = failures.recv() else {
            return;
        };
        report_blob_failure(&bridge, &failure);
        let _ = events.send(SessionEvent::BlobFailed(failure));
        thread::sleep(BLOB_BLOCK_FAILURE_EXIT_GRACE);
        std::process::exit(1);
    });
}

fn blob_failure_document(failure: &BlobBlockFailure) -> Document {
    let mut document = doc! { "type": "host.resources.failure" };
    document.insert("code", failure.code);
    document.insert("error", failure.message.clone());
    if let Some(retry_after_ms) = failure.retry_after_ms {
        document.insert("retryAfterMs", retry_after_ms as i64);
    }
    document
}

fn report_blob_failure(bridge: &HostIoBridge, failure: &BlobBlockFailure) {
    let notification = blob_failure_document(failure);
    if let Ok(packet) = crate::encode_document_packet(&notification) {
        let _ = bridge.write_raw_packet(&packet);
    }
}

fn host_closed_result(
    start_status: Option<Result<(), String>>,
    launch_ready: bool,
) -> Result<(), String> {
    match start_status {
        Some(Ok(())) if launch_ready => Ok(()),
        Some(Ok(())) => Err("host stdin closed after VM exited before init.ready".to_string()),
        Some(Err(error)) => Err(format!("VM exited after host stdin closed: {error}")),
        None if launch_ready => Ok(()),
        None => Err("host stdin closed before VM launch completed".to_string()),
    }
}

fn vm_exited_result(start_status: Result<(), String>, launch_ready: bool) -> Result<(), String> {
    match start_status {
        Ok(()) if launch_ready => Err("VM exited before host stdin closed".to_string()),
        Ok(()) => Err("VM exited before init.ready".to_string()),
        Err(error) => Err(error),
    }
}

fn is_init_ready_packet(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let Ok(document) = Document::from_reader(&packet[4..]) else {
        return false;
    };
    matches!(document.get_str("type"), Ok("init.ready"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_failure_forces_exit_before_lease_expiry() {
        let config = crate::blob_block_config();
        assert!(
            config.lease_renew_interval
                + config.lease_request_timeout
                + BLOB_BLOCK_FAILURE_EXIT_GRACE
                < config.lease_duration
        );
    }

    #[test]
    fn blob_failure_packet_preserves_close_error_details() {
        let failure = BlobBlockFailure {
            code: "lease-provider-error",
            message: "blob block lease state is uncertain: release request timed out".to_string(),
            retry_after_ms: Some(30_000),
        };
        assert_eq!(
            blob_failure_document(&failure),
            doc! {
                "type": "host.resources.failure",
                "code": "lease-provider-error",
                "error": "blob block lease state is uncertain: release request timed out",
                "retryAfterMs": 30_000i64,
            },
        );
    }

    #[test]
    fn host_close_after_ready_is_normal_shutdown() {
        assert_eq!(host_closed_result(Some(Ok(())), true), Ok(()));
        assert_eq!(host_closed_result(None, true), Ok(()));
    }

    #[test]
    fn host_close_before_ready_reports_launch_failure() {
        assert_eq!(
            host_closed_result(Some(Ok(())), false),
            Err("host stdin closed after VM exited before init.ready".to_string()),
        );
    }

    #[test]
    fn vm_exit_reports_its_launch_phase() {
        assert_eq!(
            vm_exited_result(Ok(()), false),
            Err("VM exited before init.ready".to_string()),
        );
        assert_eq!(
            vm_exited_result(Ok(()), true),
            Err("VM exited before host stdin closed".to_string()),
        );
    }

    #[test]
    fn init_ready_packet_is_detected() {
        let packet = crate::encode_document_packet(&doc! {
            "type": "init.ready",
            "rootReadonly": true,
            "initName": "sandbox-init",
        })
        .unwrap();
        assert!(is_init_ready_packet(&packet));
    }
}
