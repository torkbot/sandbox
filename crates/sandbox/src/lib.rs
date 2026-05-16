//! Host-side primitives for launching and controlling sandbox microVMs.
//!
//! The public Node.js API will live above this crate. This crate owns the
//! libkrun boundary, host services, and guest-control protocol types.

pub mod control;

/// A configured microVM that has not yet been started.
#[derive(Debug, Clone)]
pub struct MicroVmSpec {
    pub vcpus: u8,
    pub memory_mib: u32,
}

impl Default for MicroVmSpec {
    fn default() -> Self {
        Self {
            vcpus: 1,
            memory_mib: 512,
        }
    }
}
