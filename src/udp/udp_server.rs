use crate::BUFFER_POOL;
use crate::UDP_PACKET_SIZE;
use anyhow::Result;
use log::debug;
use log::error;
use log::info;
use log::warn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;

pub use crate::udp::{UdpMessage, UdpPacket, UdpReceiver, UdpSender};

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
    fn lock_state(&self) -> MutexGuard<'_, State> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("udp server state lock poisoned, recovering");
                poisoned.into_inner()
            }
        }
    }

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
                let mut payload = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                tokio::select! {
                    result = udp_socket.recv_from(&mut payload) => {
                        match result {
                            Ok((size, local_addr)) => {
                                let active = {
                                    match state.lock() {
                                        Ok(guard) => guard.active,
                                        Err(poisoned) => {
                                            warn!("udp server state lock poisoned in recv loop, recovering");
                                            poisoned.into_inner().active
                                        }
                                    }
                                };
                                if !active {
                                    debug!("drop the packet ({size}) from addr: {local_addr}");
                                    continue;
                                }

                                unsafe { payload.set_len(size); }
                                let msg = UdpMessage::Packet(UdpPacket{payload, local_addr, peer_addr: None});
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
                                match udp_socket.send_to(&p.payload, p.local_addr).await {
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
        self.lock_state().addr
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let udp_sender = self.lock_state().in_udp_sender.clone();
        udp_sender.send(UdpMessage::Quit).await?;
        Ok(())
    }

    pub fn set_active(&mut self, active: bool) {
        self.lock_state().active = active
    }

    pub fn take_receiver(&mut self) -> Result<UdpReceiver> {
        let mut state = self.lock_state();
        state.active = true;
        match state.udp_receiver.take() {
            Some(receiver) => Ok(receiver),
            None => {
                state.active = false;
                Err(anyhow::anyhow!("udp receiver already taken"))
            }
        }
    }

    pub fn put_receiver(&mut self, udp_receiver: UdpReceiver) {
        let mut state = self.lock_state();
        state.active = false;
        state.udp_receiver = Some(udp_receiver);
    }

    pub fn clone_sender(&self) -> UdpSender {
        self.lock_state().in_udp_sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn take_receiver_is_exclusive_and_recoverable() {
        let mut server = match UdpServer::bind_and_start("127.0.0.1:0".parse().unwrap()).await {
            Ok(server) => server,
            Err(e) => {
                eprintln!("udp bind not permitted in test environment: {e}");
                return;
            }
        };

        let receiver = server.take_receiver().unwrap();
        assert!(server.take_receiver().is_err());

        server.put_receiver(receiver);
        assert!(server.take_receiver().is_ok());
    }
}
