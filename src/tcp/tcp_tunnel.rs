use crate::tcp::StreamMessage;
use crate::tcp::{AsyncStream, StreamReceiver, StreamRequest};
use crate::util::stream_util::StreamUtil;
use log::{debug, error, info, warn};
use std::borrow::BorrowMut;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct TcpTunnel;

impl TcpTunnel {
    pub async fn start_serving<S: AsyncStream>(
        tunnel_out: bool,
        conn: &quinn::Connection,
        stream_receiver: &mut StreamReceiver<S>,
        pending_request: &mut Option<StreamRequest<S>>,
        stream_timeout_ms: u64,
    ) {
        loop {
            let request = match pending_request.take() {
                Some(request) => request,
                None => match stream_receiver.borrow_mut().recv().await {
                    Some(StreamMessage::Request(request)) => request,
                    _ => break,
                },
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
    }

    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        stream_timeout_ms: u64,
    ) {
        let remote_addr = &conn.remote_address();
        info!("start tcp streaming, {remote_addr} ↔  {upstream_addr:?}");

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("connection timeout: {remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed: {remote_addr}");
                    break;
                }
                Err(e) => {
                    error!("failed to open accept_bi: {remote_addr}, err: {e}");
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
                        Ok(Ok(request)) => {
                            if let Err(e) = request.set_nodelay(true) {
                                warn!("could not set TCP_NODELAY on socket {dst_addr}: {e} — this may increase latency");
                            }

                            StreamUtil::start_flowing(
                                "OUT",
                                request,
                                (quic_send, quic_recv),
                                stream_timeout_ms,
                            )
                        }
                        Ok(Err(e)) => error!("failed to connect to {dst_addr}, err: {e}"),
                        Err(_) => error!("timeout connecting to {dst_addr}"),
                    }
                }),
            };
        }
    }
}
