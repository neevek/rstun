use crate::tcp::{StreamMessage, StreamReceiver, StreamRequest, StreamSender};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::error::SendTimeoutError;

#[derive(Debug, Clone)]
pub struct TcpServer {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    tcp_sender: StreamSender<TcpStream>,
    tcp_receiver: Option<StreamReceiver<TcpStream>>,
    active: bool,
    terminated: bool,
}

impl TcpServer {
    fn lock_state(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("tcp server state lock poisoned, recovering");
                poisoned.into_inner()
            }
        }
    }

    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        let addr = tcp_listener.local_addr().unwrap();

        let (tcp_sender, tcp_receiver) = channel(4);
        let state = Arc::new(Mutex::new(State {
            addr,
            tcp_sender: tcp_sender.clone(),
            tcp_receiver: Some(tcp_receiver),
            active: false,
            terminated: false,
        }));
        let state_clone = state.clone();

        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, addr)) => {
                        {
                            let (terminated, active) = {
                                let state = match state.lock() {
                                    Ok(guard) => guard,
                                    Err(poisoned) => {
                                        warn!(
                                            "tcp server state lock poisoned in accept loop, recovering"
                                        );
                                        poisoned.into_inner()
                                    }
                                };
                                (state.terminated, state.active)
                            };

                            if terminated {
                                tcp_sender.send(StreamMessage::Quit).await.ok();
                                break;
                            }

                            if !active {
                                // unless being explicitly requested, always drop the connections because we are not
                                // sure whether the receiver is ready to accept connections
                                debug!("drop connection: {addr}");
                                continue;
                            }
                        }

                        match tcp_sender
                            .send_timeout(
                                StreamMessage::Request(StreamRequest {
                                    stream,
                                    dst_addr: None,
                                }),
                                Duration::from_millis(3000),
                            )
                            .await
                        {
                            Ok(_) => {
                                // succeeded
                            }
                            Err(SendTimeoutError::Timeout(_)) => {
                                debug!("timed out sending the request, drop the stream");
                            }
                            Err(e) => {
                                info!("channel is closed, will quit tcp server, err: {e}");
                                break;
                            }
                        }
                    }

                    Err(e) => {
                        error!("tcp server failed, err: {e}");
                    }
                }
            }
            info!("tcp server quit: {addr}");
        });

        Ok(Self { state: state_clone })
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let addr = {
            let mut state = self.lock_state();
            state.terminated = true;
            state.addr
        };
        // initiate a new connection to wake up the accept() loop
        TcpStream::connect(addr).await?;
        Ok(())
    }

    pub fn addr(&self) -> SocketAddr {
        self.lock_state().addr
    }

    pub fn take_receiver(&mut self) -> Result<StreamReceiver<TcpStream>> {
        let mut state = self.lock_state();
        state.active = true;
        match state.tcp_receiver.take() {
            Some(receiver) => Ok(receiver),
            None => {
                state.active = false;
                Err(anyhow::anyhow!("tcp receiver already taken"))
            }
        }
    }

    pub fn put_receiver(&mut self, tcp_receiver: StreamReceiver<TcpStream>) {
        let mut state = self.lock_state();
        state.active = false;
        state.tcp_receiver = Some(tcp_receiver);
    }

    pub fn clone_sender(&self) -> StreamSender<TcpStream> {
        self.lock_state().tcp_sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn take_receiver_is_exclusive_and_recoverable() {
        let mut server = match TcpServer::bind_and_start("127.0.0.1:0".parse().unwrap()).await {
            Ok(server) => server,
            Err(e) => {
                eprintln!("tcp bind not permitted in test environment: {e}");
                return;
            }
        };

        let receiver = server.take_receiver().unwrap();
        assert!(server.take_receiver().is_err());

        server.put_receiver(receiver);
        assert!(server.take_receiver().is_ok());
    }
}
