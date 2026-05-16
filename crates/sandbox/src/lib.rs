//! Host-side primitives for launching and controlling sandbox microVMs.
//!
//! The public Node.js API will live above this crate. This crate owns the
//! libkrun boundary, host services, and guest-control protocol types.

pub mod control;
pub mod config;
pub mod mounts;
pub mod runtime;
pub mod vfs;

pub use config::MicroVmSpec;
