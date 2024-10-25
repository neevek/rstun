use super::udp_packet::UdpPacket;
use crate::BUFFER_POOL;
use crate::UDP_PACKET_SIZE;
use anyhow::Result;
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

pub type UdpSender = Sender<UdpMessage>;
pub type UdpReceiver = Receiver<UdpMessage>;

#[derive(Debug, Clone)]
pub struct UdpServer(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    active: bool,
    in_udp_sender: UdpSender,
    udp_receiver: Option<UdpReceiver>,
}

impl UdpServer {
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).await?;
        let addr = udp_socket.local_addr().unwrap();

        let (in_udp_sender, mut in_udp_receiver) = channel::<UdpMessage>(4);
        let (out_udp_sender, out_udp_receiver) = channel::<UdpMessage>(4);

        let state = Arc::new(Mutex::new(State {
            addr,
            active: false,
            in_udp_sender,
            udp_receiver: Some(out_udp_receiver),
        }));
        let state_clone = state.clone();

        tokio::spawn(async move {
            loop {
                let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                tokio::select! {
                    result = udp_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((size, addr)) => {
                                let active = {
                                    state.clone().lock().unwrap().active
                                };
                                if !active {
                                    debug!("drop the packet ({size}) from addr: {addr}");
                                    continue;
                                }

                                unsafe { buf.set_len(size); }
                                let msg = UdpMessage::Packet(UdpPacket::new(buf, addr));
                                match tokio::time::timeout(
                                        Duration::from_millis(300),
                                        out_udp_sender.send(msg)).await {
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
                            Some(UdpMessage::Quit) => {
                                info!("udp server is requested to quit");
                                break;
                            }
                            None => {
                                // all senders quit
                                info!("udp server quit");
                                break;
                            }
                        }
                    }
                }
            }

            info!("udp server quit: {addr}");
        });

        Ok(Self(state_clone))
    }

    pub fn addr(&self) -> SocketAddr {
        self.0.lock().unwrap().addr
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let udp_sender = self.0.lock().unwrap().in_udp_sender.clone();
        udp_sender.send(UdpMessage::Quit).await?;
        Ok(())
    }

    pub fn set_active(&mut self, active: bool) {
        self.0.lock().unwrap().active = active
    }

    pub fn take_receiver(&mut self) -> Option<UdpReceiver> {
        self.0.lock().unwrap().udp_receiver.take()
    }

    pub fn put_receiver(&mut self, udp_receiver: UdpReceiver) {
        self.0.lock().unwrap().udp_receiver = Some(udp_receiver);
    }

    pub fn clone_udp_sender(&self) -> UdpSender {
        self.0.lock().unwrap().in_udp_sender.clone()
    }
}
