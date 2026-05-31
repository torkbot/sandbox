use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub(crate) struct SyncAsyncBridge {
    inner: Arc<Mutex<BridgeState>>,
    capacity: usize,
}

#[derive(Debug)]
pub(crate) struct AsyncBridgeIo {
    inner: Arc<Mutex<BridgeState>>,
    capacity: usize,
    extensions: rama_core::extensions::Extensions,
}

#[derive(Debug)]
struct BridgeState {
    sync_to_async: VecDeque<u8>,
    async_to_sync: VecDeque<u8>,
    async_read_waker: Option<Waker>,
    async_write_waker: Option<Waker>,
    sync_closed: bool,
    async_closed: bool,
}

impl SyncAsyncBridge {
    pub(crate) fn new(capacity: usize) -> (Self, AsyncBridgeIo) {
        let inner = Arc::new(Mutex::new(BridgeState {
            sync_to_async: VecDeque::with_capacity(capacity),
            async_to_sync: VecDeque::with_capacity(capacity),
            async_read_waker: None,
            async_write_waker: None,
            sync_closed: false,
            async_closed: false,
        }));
        (
            Self {
                inner: inner.clone(),
                capacity,
            },
            AsyncBridgeIo {
                inner,
                capacity,
                extensions: rama_core::extensions::Extensions::new(),
            },
        )
    }

    pub(crate) fn push_from_sync(&self, bytes: &[u8]) -> usize {
        let mut state = self.inner.lock().unwrap();
        if state.async_closed {
            return 0;
        }
        let writable = self.capacity.saturating_sub(state.sync_to_async.len());
        let written = writable.min(bytes.len());
        state.sync_to_async.extend(&bytes[..written]);
        if written > 0 {
            wake(&mut state.async_read_waker);
        }
        written
    }

    pub(crate) fn sync_write_capacity(&self) -> usize {
        let state = self.inner.lock().unwrap();
        if state.async_closed {
            0
        } else {
            self.capacity.saturating_sub(state.sync_to_async.len())
        }
    }

    pub(crate) fn pull_to_sync(&self, output: &mut [u8]) -> usize {
        let mut state = self.inner.lock().unwrap();
        let read = output.len().min(state.async_to_sync.len());
        for byte in &mut output[..read] {
            *byte = state.async_to_sync.pop_front().unwrap();
        }
        if read > 0 {
            wake(&mut state.async_write_waker);
        }
        read
    }

    pub(crate) fn close_sync(&self) {
        let mut state = self.inner.lock().unwrap();
        state.sync_closed = true;
        wake(&mut state.async_read_waker);
    }

    pub(crate) fn async_is_closed(&self) -> bool {
        self.inner.lock().unwrap().async_closed
    }

    pub(crate) fn async_to_sync_is_empty(&self) -> bool {
        self.inner.lock().unwrap().async_to_sync.is_empty()
    }
}

impl AsyncRead for AsyncBridgeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.inner.lock().unwrap();
        let read = buf.remaining().min(state.sync_to_async.len());
        if read > 0 {
            let mut bytes = Vec::with_capacity(read);
            for _ in 0..read {
                bytes.push(state.sync_to_async.pop_front().unwrap());
            }
            buf.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }
        if state.sync_closed {
            return Poll::Ready(Ok(()));
        }
        state.async_read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for AsyncBridgeIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut state = self.inner.lock().unwrap();
        if state.sync_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sync side closed",
            )));
        }
        let writable = self.capacity.saturating_sub(state.async_to_sync.len());
        if writable == 0 {
            state.async_write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let written = writable.min(buf.len());
        state.async_to_sync.extend(&buf[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut state = self.inner.lock().unwrap();
        state.async_closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for AsyncBridgeIo {
    fn drop(&mut self) {
        let mut state = self.inner.lock().unwrap();
        state.async_closed = true;
    }
}

impl rama_core::extensions::ExtensionsRef for AsyncBridgeIo {
    fn extensions(&self) -> &rama_core::extensions::Extensions {
        &self.extensions
    }
}

fn wake(waker: &mut Option<Waker>) {
    if let Some(waker) = waker.take() {
        waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::rt::Executor;
    use rama_core::service::service_fn;
    use rama_http::{Body, Request, Response, StatusCode};
    use rama_http_backend::server::HttpServer;
    use std::convert::Infallible;
    use std::thread;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn async_reader_receives_sync_bytes() {
        let (sync, mut async_io) = SyncAsyncBridge::new(1024);
        let runtime = tokio::runtime::Runtime::new().unwrap();

        sync.push_from_sync(b"hello");
        let output = runtime.block_on(async {
            let mut output = vec![0; 5];
            async_io.read_exact(&mut output).await.unwrap();
            output
        });

        assert_eq!(output, b"hello");
        sync.close_sync();
    }

    #[test]
    fn sync_reader_receives_async_bytes() {
        let (sync, mut async_io) = SyncAsyncBridge::new(1024);
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            async_io.write_all(b"world").await.unwrap();
            async_io.shutdown().await.unwrap();
        });
        let mut output = [0; 5];
        assert_eq!(sync.pull_to_sync(&mut output), 5);
        assert_eq!(&output, b"world");
        assert!(sync.async_is_closed());
    }

    #[test]
    fn rama_http_server_can_serve_over_bridge_io() {
        let (sync, async_io) = SyncAsyncBridge::new(16 * 1024);
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.spawn(async move {
            let server = HttpServer::auto(Executor::default());
            let service = service_fn(|_request: Request| async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("rama bridge ok"))
                        .unwrap(),
                )
            });
            let _ = server.serve(async_io, service).await;
        });

        sync.push_from_sync(b"GET / HTTP/1.1\r\nHost: bridge.test\r\nConnection: close\r\n\r\n");
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut response = Vec::new();
        while Instant::now() < deadline {
            let mut buffer = [0; 1024];
            let read = sync.pull_to_sync(&mut buffer);
            if read > 0 {
                response.extend_from_slice(&buffer[..read]);
                if response
                    .windows(14)
                    .any(|window| window == b"rama bridge ok")
                {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let response = String::from_utf8(response).unwrap();
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("rama bridge ok"), "{response}");
    }
}
