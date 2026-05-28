use std::io;

use crate::http_interception::HttpRequestProtocol;
use crate::network_service::HostTlsMetadata;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedDestination {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedHttpRequest {
    pub protocol: HttpRequestProtocol,
    pub method: String,
    pub url: String,
    pub source: InterceptedDestination,
    pub original_destination: InterceptedDestination,
    pub upstream_dial: InterceptedDestination,
    pub headers: Vec<(String, String)>,
    pub tls: Option<HostTlsMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedHttpResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub trait HttpHookExecutor: Send + Sync + std::fmt::Debug {
    fn apply_request_headers(
        &self,
        request: InterceptedHttpRequest,
    ) -> io::Result<Vec<(String, String)>>;

    fn rejects_rebound_authority(
        &self,
        scheme: &str,
        authority: &str,
        original_destination: &InterceptedDestination,
        upstream_dial: &InterceptedDestination,
    ) -> bool;
}

pub trait HttpInterceptRuntime: Send + Sync + std::fmt::Debug {
    fn handle_request_head(
        &self,
        request: InterceptedHttpRequest,
    ) -> io::Result<InterceptedHttpRequest>;

    fn rejects_rebound_authority(
        &self,
        scheme: &str,
        authority: &str,
        original_destination: &InterceptedDestination,
        upstream_dial: &InterceptedDestination,
    ) -> bool;
}

#[derive(Debug, Clone)]
pub struct HookBackedHttpInterceptRuntime<H> {
    hooks: H,
}

impl<H> HookBackedHttpInterceptRuntime<H> {
    pub fn new(hooks: H) -> Self {
        Self { hooks }
    }
}

impl<H> HttpInterceptRuntime for HookBackedHttpInterceptRuntime<H>
where
    H: HttpHookExecutor,
{
    fn handle_request_head(
        &self,
        mut request: InterceptedHttpRequest,
    ) -> io::Result<InterceptedHttpRequest> {
        request.headers = self.hooks.apply_request_headers(request.clone())?;
        Ok(request)
    }

    fn rejects_rebound_authority(
        &self,
        scheme: &str,
        authority: &str,
        original_destination: &InterceptedDestination,
        upstream_dial: &InterceptedDestination,
    ) -> bool {
        self.hooks
            .rejects_rebound_authority(scheme, authority, original_destination, upstream_dial)
    }
}
