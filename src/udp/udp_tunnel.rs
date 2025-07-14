use crate::{
    tunnel_message::{TunnelMessage, UdpLocalAddr, UdpPeerAddr},
    udp::{udp_server::UdpMessage, UdpPacket},
    util::stream_util::StreamUtil,
    BUFFER_POOL, UDP_PACKET_SIZE,
};
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
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};

type TSafe<T> = Arc<tokio::sync::Mutex<T>>;

pub struct UdpTunnel;

impl UdpTunnel {
    pub async fn start_serving(
        conn: &quinn::Connection,
        udp_sender: &Sender<UdpMessage>,
        udp_receiver: &mut Receiver<UdpMessage>,
        udp_timeout_ms: u64,
    ) {
        debug!("start transfering udp packets");
        let stream_map = Arc::new(DashMap::new());
        while let Some(UdpMessage::Packet(packet)) = udp_receiver.recv().await {
            let quic_send = match UdpTunnel::open_stream(
                conn.clone(),
                udp_sender.clone(),
                packet.local_addr,
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

                warn!(">>>>>>>>>>> haha send 1");

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
    }

    async fn open_stream(
        conn: Connection,
        udp_sender: Sender<UdpMessage>,
        local_addr: SocketAddr,
        stream_map: Arc<DashMap<SocketAddr, TSafe<SendStream>>>,
        udp_timeout_ms: u64,
    ) -> Result<TSafe<SendStream>> {
        if let Some(s) = stream_map.get(&local_addr) {
            return Ok((*s).clone());
        }

        let (mut quic_send, mut quic_recv) =
            conn.open_bi().await.context("open_bi failed for udp out")?;

        debug!(
            "new udp session: {local_addr}, streams: {}",
            stream_map.len()
        );

        let quic_send = Arc::new(tokio::sync::Mutex::new(quic_send));
        stream_map.insert(local_addr, quic_send.clone());

        let stream_map = stream_map.clone();
        tokio::spawn(async move {
            debug!(
                "start udp stream: {local_addr}, streams: {}",
                stream_map.len()
            );
            loop {
                let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                match tokio::time::timeout(Duration::from_millis(udp_timeout_ms), async {
                    warn!(">>>>>> haha read 1");
                    let peer_addr = match TunnelMessage::recv(&mut quic_recv).await? {
                        TunnelMessage::ReqUdpPacketStart(UdpPeerAddr(addr)) => addr,
                        msg => {
                            log_and_bail!("unexpected tunnel message: {msg}");
                        }
                    };
                    warn!(">>>>>> haha addr:{peer_addr:?}");
                    let packet_len = TunnelMessage::recv_raw(&mut quic_recv, &mut buf).await?;
                    Ok((peer_addr, packet_len))
                })
                .await
                {
                    Ok(Ok((peer_addr, packet_len))) => {
                        unsafe {
                            buf.set_len(packet_len as usize);
                        }
                        let packet = UdpPacket::new(buf, local_addr, peer_addr);
                        udp_sender.send(UdpMessage::Packet(packet)).await.ok();
                    }
                    e => {
                        match e {
                            Ok(Err(e)) => {
                                warn!("failed to read for udp, err: {e}");
                            }
                            Err(_) => {
                                // timedout
                                // debug!("timeout on reading udp packet");
                            }
                            _ => unreachable!(""),
                        }
                        break;
                    }
                }
            }

            stream_map.remove(&local_addr);
            debug!(
                "drop udp session: {local_addr}, streams: {}",
                stream_map.len()
            );
        });

        Ok(quic_send)
    }

    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: SocketAddr,
        udp_timeout_ms: u64,
    ) {
        let remote_addr = &conn.remote_address();
        info!("start udp streaming, {remote_addr} ↔  {upstream_addr}");

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut { .. }) => {
                    info!("connection timeout: {remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed: {remote_addr}");
                    break;
                }
                Err(e) => {
                    error!("failed to accpet_bi: {remote_addr}, err: {e}");
                    break;
                }
                Ok((quic_send, quic_recv)) => tokio::spawn(async move {
                    Self::process(quic_send, quic_recv, upstream_addr, udp_timeout_ms).await
                }),
            };
        }

        info!("connection for udp out is dropped");
    }

    async fn process(
        mut quic_send: SendStream,
        mut quic_recv: RecvStream,
        upstream_addr: SocketAddr,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let peer_addr = match TunnelMessage::recv(&mut quic_recv).await {
            Ok(TunnelMessage::ReqUdpStart(peer_addr)) => peer_addr.0,
            _ => {
                log_and_bail!("unexpected first udp message");
            }
        };
        debug!("new udp session: {peer_addr:?}");

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let udp_socket = match UdpSocket::bind(local_addr).await {
            Ok(udp_socket) => Arc::new(udp_socket),
            Err(e) => {
                log_and_bail!("failed to bind to localhost, err: {e:?}");
            }
        };

        if let Err(e) = udp_socket.connect(upstream_addr).await {
            log_and_bail!("failed to connect to upstream: {upstream_addr}, err: {e:?}");
        };

        let udp_socket_clone = udp_socket.clone();
        tokio::spawn(async move {
            debug!("start udp stream: {peer_addr:?} ←  {upstream_addr}");
            let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
            loop {
                match tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    udp_socket_clone.recv(&mut buf),
                )
                .await
                {
                    Ok(Ok(len)) => {
                        TunnelMessage::send_raw(&mut quic_send, &buf[..len])
                            .await
                            .ok();
                    }
                    e => {
                        match e {
                            Ok(Err(e)) => {
                                warn!("failed to receive datagrams from upstream: {upstream_addr}, err: {e:?}");
                            }
                            Err(_) => {
                                debug!(
                                    "timeout on receiving datagrams from upstream: {upstream_addr}"
                                );
                            }
                            _ => unreachable!(""),
                        }
                        break;
                    }
                }
            }
            debug!("drop udp stream: {peer_addr} ←  {upstream_addr}");
        });

        debug!("start sending datagrams to upstream, {peer_addr} →  {upstream_addr}");
        let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
        loop {
            match tokio::time::timeout(
                Duration::from_millis(udp_timeout_ms),
                TunnelMessage::recv_raw(&mut quic_recv, &mut buf),
            )
            .await
            {
                Ok(Ok(len)) => {
                    udp_socket
                        .send(&buf[..len as usize])
                        .await
                        .context("failed to send datagram through udp_socket")?;
                }
                e => {
                    match e {
                        Ok(Err(e)) => {
                            warn!("failed to read from udp packet from tunnel, err: {e:?}");
                        }
                        Err(_) => {
                            debug!("timeout on reading udp packet from tunnel");
                        }
                        _ => unreachable!(""),
                    }
                    break;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }
}
