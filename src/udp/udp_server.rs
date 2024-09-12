use super::udp_packet::UdpPacket;
use anyhow::Result;
use bytes::BytesMut;
use log::debug;
use log::error;
use log::info;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;

pub enum UdpMessage {
    Packet(UdpPacket),
    Quit,
}

type UdpSender = Sender<UdpMessage>;
type UdpReceiver = Receiver<UdpMessage>;

#[derive(Debug, Clone)]
pub struct UdpServer(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    active: Arc<Mutex<bool>>,
    in_udp_sender: UdpSender,
    out_udp_sender: UdpSender,
    udp_receiver: Option<UdpReceiver>,
}

impl UdpServer {
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).await.map_err(|e| {
            error!("udp server failed to bind on '{addr}', error: {e}");
            e
        })?;

        let addr = udp_socket.local_addr().unwrap();
        info!("bound udp server to: {addr}");

        let (in_udp_sender, mut in_udp_receiver) = channel::<UdpMessage>(4);
        let (out_udp_sender, out_udp_receiver) = channel::<UdpMessage>(4);
        let out_udp_sender_clone = out_udp_sender.clone();

        let active = Arc::new(Mutex::new(false));
        let active_clone = active.clone();

        tokio::spawn(async move {
            loop {
                let mut buf = BytesMut::zeroed(1500);
                tokio::select! {
                    result = udp_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((size, addr)) => {
                                if !*active.lock().unwrap() {
                                    debug!("drop the packet ({size}) from addr: {addr}");
                                    continue;
                                }

                                let payload = buf.split_to(size);
                                let msg = UdpMessage::Packet(UdpPacket::new(payload.freeze(), addr));
                                match tokio::time::timeout(
                                        Duration::from_millis(300),
                                        out_udp_sender_clone.send(msg)).await {
                                    Ok(Ok(_)) => {
                                        // succeeded
                                    }
                                    Err(_) => {
                                        // timeout
                                    }
                                    Ok(Err(e)) => {
                                        error!("receiving end of the channel is closed, will quit. err: {e}");
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("failed to read from local udp socket, err: {e}");
                            }
                        }
                    }

                    result = in_udp_receiver.recv() => {
                        match result {
                            Some(UdpMessage::Packet(p)) => {
                                match udp_socket.send_to(&p.payload, p.addr).await {
                                    Ok(_) => {
                                        // succeeded
                                    }
                                    Err(e) => {
                                        error!("failed to send packet to local, err: {e}");
                                    }
                                }
                            }
                            Some(_) => {
                                continue;
                            }
                            None => {
                                // all senders quit
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self(Arc::new(Mutex::new(State {
            addr,
            active: active_clone,
            in_udp_sender,
            out_udp_sender,
            udp_receiver: Some(out_udp_receiver),
        }))))
    }

    pub fn addr(&self) -> SocketAddr {
        self.0.lock().unwrap().addr
    }

    pub fn set_active(&mut self, active: bool) {
        *self.0.lock().unwrap().active.lock().unwrap() = active
    }

    pub fn take_receiver(&mut self) -> Option<UdpReceiver> {
        self.0.lock().unwrap().udp_receiver.take()
    }

    pub fn put_receiver(&mut self, udp_receiver: UdpReceiver) {
        self.0.lock().unwrap().udp_receiver = Some(udp_receiver);
    }

    pub async fn pause(&mut self) {
        debug!("pausing the local udp server...");
        let out_udp_sender = self.0.lock().unwrap().out_udp_sender.clone();
        out_udp_sender.send(UdpMessage::Quit).await.ok();
    }

    pub fn clone_udp_sender(&self) -> UdpSender {
        self.0.lock().unwrap().in_udp_sender.clone()
    }
}
