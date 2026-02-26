use crate::tcp::StreamMessage;
use crate::tcp::{AsyncStream, StreamReceiver, StreamRequest};
use crate::util::stream_util::StreamUtil;
use crate::{ChannelTcpConnectCtx, ChannelTcpConnector};
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
    pub async fn start_dynamic_accepting(
        conn: &quinn::Connection,
        default_upstream: Option<SocketAddr>,
        stream_timeout_ms: u64,
        tcp_connector: Option<ChannelTcpConnector>,
    ) -> Result<()> {
        if let Some(connector) = tcp_connector {
            Self::start_accepting_with_connector(
                conn,
                default_upstream,
                stream_timeout_ms,
                Some(connector),
            )
            .await
        } else {
            Self::start_accepting(conn, None, stream_timeout_ms).await
        }
    }

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
        Self::start_accepting_with_connector(conn, upstream_addr, stream_timeout_ms, None).await
    }

    pub async fn start_accepting_with_connector(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        stream_timeout_ms: u64,
        tcp_connector: Option<ChannelTcpConnector>,
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
                Ok((quic_send, mut quic_recv)) => {
                    let tcp_connector = tcp_connector.clone();
                    tokio::spawn(async move {
                        let requested_dst = if tcp_connector.is_some() || upstream_addr.is_none() {
                            match StreamUtil::read_socket_addr(&mut quic_recv, stream_timeout_ms)
                                .await
                            {
                                Ok(dst_addr) => Some(dst_addr),
                                Err(e) => {
                                    log::error!("failed to read dst address: {e}");
                                    return;
                                }
                            }
                        } else {
                            None
                        };

                        let upstream_stream = if let Some(connector) = tcp_connector {
                            let ctx = ChannelTcpConnectCtx {
                                requested_dst,
                                default_upstream: upstream_addr,
                                timeout_ms: stream_timeout_ms,
                            };
                            match connector(ctx).await {
                                Ok(stream) => stream,
                                Err(e) => {
                                    error!("failed to connect via custom channel connector: {e}");
                                    return;
                                }
                            }
                        } else {
                            let dst_addr = match upstream_addr.or(requested_dst) {
                                Some(dst_addr) => dst_addr,
                                None => {
                                    error!("no destination available for accepted stream");
                                    return;
                                }
                            };

                            match tokio::time::timeout(
                                Duration::from_secs(5),
                                TcpStream::connect(&dst_addr),
                            )
                            .await
                            {
                                Ok(Ok(request)) => request,
                                Ok(Err(e)) => {
                                    error!(
                                        "failed to connect upstream, dst_addr:{dst_addr}, err:{e}"
                                    );
                                    return;
                                }
                                Err(_) => {
                                    error!("tcp connect timed out, dst_addr:{dst_addr}");
                                    return;
                                }
                            }
                        };

                        StreamUtil::start_flowing(
                            "OUT",
                            upstream_stream,
                            (quic_send, quic_recv),
                            stream_timeout_ms,
                        );
                    });
                }
            };
        }

        Ok(())
    }
}
