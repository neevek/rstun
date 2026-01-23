use crate::tcp::{StreamMessage, StreamReceiver, StreamRequest, StreamSender};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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
                        if let Err(e) = stream.set_nodelay(true) {
                            warn!("could not set TCP_NODELAY on socket {addr}: {e} — this may increase latency");
                        }

                        {
                            let (terminated, active) = {
                                let state = state.lock().unwrap();
                                (state.terminated, state.active)
                            };

                            if terminated {
                                tcp_sender.send(StreamMessage::Quit).await.ok();
                                break;
                            }

                            if !active {
                                // unless being explicitly requested, always drop the connections because we are not
                                // sure whether the receiver is ready to aceept connections
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
                                debug!("timedout sending the request, drop the stream");
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
            let mut state = self.state.lock().unwrap();
            state.terminated = true;
            state.addr
        };
        // initiate a new connection to wake up the accept() loop
        TcpStream::connect(addr).await?;
        Ok(())
    }

    pub fn addr(&self) -> SocketAddr {
        self.state.lock().unwrap().addr
    }

    pub fn take_receiver(&mut self) -> StreamReceiver<TcpStream> {
        let mut state = self.state.lock().unwrap();
        state.active = true;
        state.tcp_receiver.take().unwrap()
    }

    pub fn put_receiver(&mut self, tcp_receiver: StreamReceiver<TcpStream>) {
        let mut state = self.state.lock().unwrap();
        state.active = false;
        state.tcp_receiver = Some(tcp_receiver);
    }

    pub fn clone_sender(&self) -> StreamSender<TcpStream> {
        self.state.lock().unwrap().tcp_sender.clone()
    }
}
