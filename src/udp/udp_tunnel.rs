use crate::BUFFER_POOL;
use crate::UDP_PACKET_SIZE;
use crate::tunnel_message::{TunnelMessage, UdpPeerAddr};
use crate::udp::{UdpMessage, UdpPacket};
use anyhow::{Context, Result};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use quinn::{Connection, RecvStream, SendStream};
use rs_utilities::log_and_bail;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio::{net::UdpSocket, sync::Mutex};

type TSafe<T> = Arc<tokio::sync::Mutex<T>>;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct UdpStreamKey {
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
}

pub struct UdpTunnel;

impl UdpTunnel {
    pub async fn start_serving(
        conn: &quinn::Connection,
        udp_sender: &Sender<UdpMessage>,
        udp_receiver: &mut Receiver<UdpMessage>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        debug!("start serving udp via: {}", conn.remote_address());
        let stream_map = Arc::new(DashMap::new());
        while let Some(UdpMessage::Packet(packet)) = udp_receiver.recv().await {
            let stream_key = UdpStreamKey {
                local_addr: packet.local_addr,
                peer_addr: packet.peer_addr,
            };
            let quic_send = match UdpTunnel::open_stream(
                conn.clone(),
                udp_sender.clone(),
                stream_key,
                stream_map.clone(),
                udp_timeout_ms,
            )
            .await
            {
                Ok(quic_send) => quic_send,
                Err(e) => {
                    error!("{e}");
                    if conn.close_reason().is_some() {
                        debug!("connection is closed, will quit");
                        break;
                    }
                    continue;
                }
            };

            // send the packet using an async task
            tokio::spawn(async move {
                let mut quic_send = quic_send.lock().await;
                let payload_len = packet.payload.len();

                TunnelMessage::send(
                    &mut quic_send,
                    &TunnelMessage::ReqUdpStart(UdpPeerAddr(packet.peer_addr)),
                )
                .await
                .ok();

                TunnelMessage::send_raw(&mut quic_send, &packet.payload)
                    .await
                    .inspect_err(|e| {
                        warn!(
                            "failed to send datagram({payload_len}) through the tunnel, err: {e}"
                        );
                    })
                    .ok();
            });
        }

        info!("udp server quit");

        Ok(())
    }

    async fn open_stream(
        conn: Connection,
        udp_sender: Sender<UdpMessage>,
        stream_key: UdpStreamKey,
        stream_map: Arc<DashMap<UdpStreamKey, TSafe<SendStream>>>,
        udp_timeout_ms: u64,
    ) -> Result<TSafe<SendStream>> {
        if let Some(s) = stream_map.get(&stream_key) {
            return Ok((*s).clone());
        }

        let (quic_send, mut quic_recv) =
            conn.open_bi().await.context("open_bi failed for udp out")?;

        let quic_send = Arc::new(Mutex::new(quic_send));
        stream_map.insert(stream_key, quic_send.clone());

        let stream_map = stream_map.clone();
        tokio::spawn(async move {
            debug!(
                "start udp stream: {:?}, streams: {}",
                stream_key,
                stream_map.len(),
            );
            loop {
                let mut payload = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                match tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    TunnelMessage::recv_raw(&mut quic_recv, &mut payload),
                )
                .await
                {
                    Ok(Ok(packet_len)) => {
                        unsafe {
                            payload.set_len(packet_len as usize);
                        }
                        let packet = UdpPacket {
                            payload,
                            local_addr: stream_key.local_addr,
                            peer_addr: stream_key.peer_addr,
                        };
                        let _ = udp_sender.send(UdpMessage::Packet(packet)).await;
                    }
                    Ok(Err(_)) => {
                        // warn!("failed to read for udp, err: {e}");
                        break;
                    }
                    Err(_) => {
                        // Timeout occurred
                        break;
                    }
                }
            }

            stream_map.remove(&stream_key);
            debug!(
                "dropped udp stream: {:?}, streams: {}",
                stream_key,
                stream_map.len(),
            );
        });

        Ok(quic_send)
    }

    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let remote_addr = &conn.remote_address();
        info!("start udp stream, {remote_addr} ↔  {upstream_addr:?}");

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
                    error!("failed to accept_bi: {remote_addr}, err: {e}");
                    break;
                }
                Ok((quic_send, quic_recv)) => tokio::spawn(async move {
                    Self::process(quic_send, quic_recv, upstream_addr, udp_timeout_ms).await
                }),
            };
        }

        info!("connection for udp out is dropped");

        Ok(())
    }

    async fn process(
        quic_send: SendStream,
        mut quic_recv: RecvStream,
        upstream_addr: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let quic_send = Arc::new(Mutex::new(quic_send));
        let mut udp_socket = None;
        if let Some(upstream_addr) = upstream_addr {
            // pre-create the udp-socket if upstream is specified
            udp_socket = Self::create_peer_socket_and_exchange_data(
                upstream_addr,
                quic_send.clone(),
                udp_timeout_ms,
            )
            .await?;
        }

        let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
        loop {
            match tokio::time::timeout(Duration::from_millis(udp_timeout_ms), async {
                let peer_addr = match TunnelMessage::recv(&mut quic_recv).await? {
                    TunnelMessage::ReqUdpStart(UdpPeerAddr(peer_addr)) => peer_addr,
                    msg => {
                        log_and_bail!("unexpected tunnel message: {msg}");
                    }
                };

                let packet_len = TunnelMessage::recv_raw(&mut quic_recv, &mut buf).await?;
                Ok((peer_addr, packet_len))
            })
            .await
            {
                Ok(Ok((peer_addr, packet_len))) => {
                    match peer_addr {
                        Some(peer_addr) => {
                            if let Some(upstream_addr) = upstream_addr {
                                warn!(
                                    "upstream_addr {upstream_addr:?} is specified for the connection, peer_addr {peer_addr} is ignored"
                                );
                            } else if udp_socket.as_ref().and_then(|sock| sock.0.peer_addr().ok())
                                != Some(peer_addr)
                            {
                                if let Some(udp_socket) = udp_socket {
                                    // shutdown the old socket
                                    udp_socket.1.send(()).ok();
                                }
                                udp_socket = Self::create_peer_socket_and_exchange_data(
                                    peer_addr,
                                    quic_send.clone(),
                                    udp_timeout_ms,
                                )
                                .await?;
                            }
                        }
                        None => {
                            if udp_socket.is_none() {
                                log_and_bail!("no valid upstream_addr to connect");
                            }
                        }
                    };

                    udp_socket
                        .as_ref()
                        .unwrap()
                        .0
                        .send(&buf[..packet_len as usize])
                        .await
                        .context("failed to send datagram through udp_socket")?;
                }
                Ok(Err(e)) => {
                    warn!("failed to read from udp packet from tunnel, err: {e}");
                    break;
                }
                Err(_) => {
                    // timeout on receiving datagrams from upstream
                    break;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }

    async fn create_peer_socket_and_exchange_data(
        addr: SocketAddr,
        quic_send: Arc<Mutex<SendStream>>,
        udp_timeout_ms: u64,
    ) -> Result<Option<(Arc<UdpSocket>, oneshot::Sender<()>)>> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        match UdpSocket::bind(local_addr).await {
            Ok(udp_socket) => {
                if let Err(e) = udp_socket.connect(addr).await {
                    log_and_bail!("failed to connect to upstream: {addr}, err: {e}");
                };

                let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
                let udp_socket = Arc::new(udp_socket);

                Self::udp_to_quic(
                    udp_socket.clone(),
                    quic_send.clone(),
                    udp_timeout_ms,
                    shutdown_rx,
                );

                Ok(Some((udp_socket, shutdown_tx)))
            }
            Err(e) => {
                log_and_bail!("failed to bind to localhost, err: {e}");
            }
        }
    }

    fn udp_to_quic(
        udp_socket: Arc<UdpSocket>,
        quic_send: Arc<Mutex<SendStream>>,
        udp_timeout_ms: u64,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        tokio::spawn(async move {
            debug!("start udp stream →  {:?}", udp_socket.peer_addr());
            let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
            loop {
                tokio::select! {
                    biased;

                    _ = &mut shutdown_rx => {
                        break;
                    }

                    result = tokio::time::timeout(
                        Duration::from_millis(udp_timeout_ms),
                        udp_socket.recv(&mut buf)
                    ) => {
                        match result {
                            Ok(Ok(len)) => {
                                let mut quic_send = quic_send.lock().await;
                                TunnelMessage::send_raw(&mut quic_send, &buf[..len])
                                    .await
                                    .ok();
                            }
                            Ok(Err(e)) => {
                                warn!("failed to receive datagrams from upstream, err: {e:?}");
                                break;
                            }
                            Err(_) => {
                                // timeout on receiving datagrams from upstream
                                break;
                            }
                        }
                    }
                }
            }
            debug!("dropped udp stream →  {:?}", udp_socket.peer_addr());
        });
    }
}
