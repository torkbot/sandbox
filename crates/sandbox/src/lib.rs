//! Host-side primitives for launching and controlling sandbox microVMs.
//!
//! The public Node.js API will live above this crate. This crate owns the
//! libkrun boundary, host services, and guest-control protocol types.

mod async_bridge;
pub mod block_storage;
pub mod config;
pub mod control;
pub mod http_flow;
pub mod http_interception;
pub mod mounts;
pub mod network;
pub mod network_service;
pub mod rootfs_image;
pub mod runtime;
pub mod vfs;

pub use config::MicroVmSpec;
