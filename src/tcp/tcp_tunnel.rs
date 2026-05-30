use crate::tcp::StreamMessage;
use crate::tcp::{AsyncStream, StreamReceiver, StreamRequest};
use crate::util::stream_util::StreamUtil;
use crate::{ChannelTcpConnectCtx, ChannelTcpConnector, format_optional_socket_addr};
use anyhow::Result;
use log::{debug, warn};
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
                        StreamUtil::write_tunnel_target(&mut quic_send, &request.target, false)
                            .await
                    {
                        warn!("[tcp] send target failed, err={e}");
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
                    warn!("[tcp] open stream failed, err={e}");
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
        let upstream_addr_label = format_optional_socket_addr(upstream_addr);
        debug!(
            "[tcp] accept loop started, remote_addr={remote_addr}, upstream={upstream_addr_label}"
        );

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut) => {
                    debug!("[tcp] accept loop idle timeout, remote_addr={remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("[tcp] accept loop peer closed, remote_addr={remote_addr}");
                    break;
                }
                Err(e) => {
                    warn!("[tcp] accept failed, remote_addr={remote_addr}, err={e}");
                    break;
                }
                Ok((quic_send, mut quic_recv)) => {
                    let tcp_connector = tcp_connector.clone();
                    tokio::spawn(async move {
                        let requested_dst = if tcp_connector.is_some() || upstream_addr.is_none() {
                            match StreamUtil::read_tunnel_target(&mut quic_recv, stream_timeout_ms)
                                .await
                            {
                                Ok(target) => Some(target),
                                Err(e) => {
                                    warn!("[tcp] read target failed, err={e}");
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
                                    warn!("[tcp] channel connector failed, err={e}");
                                    return;
                                }
                            }
                        } else {
                            // Prefer a fixed upstream; otherwise use the requested target.
                            let target = match upstream_addr
                                .map(crate::TunnelTarget::Addr)
                                .or(requested_dst)
                            {
                                Some(target) => target,
                                None => {
                                    warn!("[tcp] no destination for accepted stream");
                                    return;
                                }
                            };

                            let connect_result = match &target {
                                crate::TunnelTarget::Addr(addr) => {
                                    tokio::time::timeout(
                                        Duration::from_secs(5),
                                        TcpStream::connect(addr),
                                    )
                                    .await
                                }
                                crate::TunnelTarget::Domain(host, port) => {
                                    tokio::time::timeout(
                                        Duration::from_secs(5),
                                        TcpStream::connect((host.as_str(), *port)),
                                    )
                                    .await
                                }
                            };

                            match connect_result {
                                Ok(Ok(request)) => request,
                                Ok(Err(e)) => {
                                    warn!("[tcp] upstream connect failed, dst={target}, err={e}");
                                    return;
                                }
                                Err(_) => {
                                    warn!("[tcp] upstream connect timeout, dst={target}");
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

        debug!("[tcp] accept loop stopped, remote_addr={remote_addr}");
        Ok(())
    }
}
