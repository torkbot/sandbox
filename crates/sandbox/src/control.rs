//! Guest control channel model.
//!
//! libkrun exposes vsock-to-UNIX-socket mappings. The Node.js package should
//! adapt one of those sockets to TorkBot's `Transport` shape: an async stream
//! of decoded messages plus async `send` and `close`.

/// Reserved guest vsock port for the init control plane.
pub const INIT_CONTROL_PORT: u32 = 1024;

/// Minimal envelope for messages exchanged between the host runtime and guest
/// init before higher-level RPC framing is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEnvelope {
    pub stream_id: u64,
    pub payload: Vec<u8>,
}
