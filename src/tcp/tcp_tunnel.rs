use crate::tcp::StreamMessage;
use crate::tcp::{AsyncStream, StreamReceiver, StreamRequest};
use crate::util::stream_util::StreamUtil;
use anyhow::Result;
use log::{debug, error, info};
use std::borrow::BorrowMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

pub struct TcpTunnel;

impl TcpTunnel {
    pub async fn start_serving<S: AsyncStream>(
        tunnel_out: bool,
        conn: &quinn::Connection,
        stream_receiver: Arc<AsyncMutex<StreamReceiver<S>>>,
        pending_request: &mut Option<StreamRequest<S>>,
        stream_timeout_ms: u64,
    ) -> Result<()> {
        loop {
            let request = match pending_request.take() {
                Some(request) => request,
                None => {
                    let mut receiver = stream_receiver.lock().await;
                    match receiver.borrow_mut().recv().await {
                        Some(StreamMessage::Request(request)) => request,
                        _ => break,
                    }
                }
            };

            match conn.open_bi().await {
                Ok((mut quic_send, quic_recv)) => {
                    if let Err(e) =
                        StreamUtil::write_socket_addr(&mut quic_send, &request.dst_addr, false)
                            .await
                    {
                        error!("failed to send dst addr: {e}");
                        *pending_request = Some(request);
                        continue;
                    }
                    StreamUtil::start_flowing(
                        if tunnel_out { "OUT" } else { "IN" },
                        request.stream,
                        (quic_send, quic_recv),
                        stream_timeout_ms,
                    )
                }
                Err(e) => {
                    error!("failed to open_bi, will retry: {e}");
                    *pending_request = Some(request);
                    break;
                }
            }
        }
        // the tcp server will be reused when tunnel reconnects
        Ok(())
    }

    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        stream_timeout_ms: u64,
    ) -> Result<()> {
        let remote_addr = &conn.remote_address();
        info!(
            "tcp accept loop started, remote_addr:{remote_addr}, upstream_addr:{upstream_addr:?}"
        );

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("tcp accept loop timed out, remote_addr:{remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("tcp accept loop closed, remote_addr:{remote_addr}");
                    break;
                }
                Err(e) => {
                    error!("failed to accept tcp bi stream, remote_addr:{remote_addr}, err:{e}");
                    break;
                }
                Ok((quic_send, mut quic_recv)) => tokio::spawn(async move {
                    let dst_addr = match upstream_addr {
                        Some(dst_addr) => dst_addr,
                        None => {
                            match StreamUtil::read_socket_addr(&mut quic_recv, stream_timeout_ms)
                                .await
                            {
                                Ok(dst_addr) => dst_addr,
                                Err(e) => {
                                    log::error!("failed to read dst address: {e}");
                                    return;
                                }
                            }
                        }
                    };

                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        TcpStream::connect(&dst_addr),
                    )
                    .await
                    {
                        Ok(Ok(request)) => StreamUtil::start_flowing(
                            "OUT",
                            request,
                            (quic_send, quic_recv),
                            stream_timeout_ms,
                        ),
                        Ok(Err(e)) => {
                            error!("failed to connect upstream, dst_addr:{dst_addr}, err:{e}")
                        }
                        Err(_) => error!("tcp connect timed out, dst_addr:{dst_addr}"),
                    }
                }),
            };
        }

        Ok(())
    }
}
