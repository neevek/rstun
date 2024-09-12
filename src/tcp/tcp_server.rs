use anyhow::Result;
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub enum ChannelMessage {
    Request(TcpStream),
    Stop,
}

#[derive(Debug)]
pub struct TcpServer {
    addr: SocketAddr,
    tcp_sender: Sender<Option<ChannelMessage>>,
    tcp_receiver: Option<Receiver<Option<ChannelMessage>>>,
    active: Arc<Mutex<bool>>,
}

impl TcpServer {
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        info!("starting tcp server, addr: {addr}");
        let tcp_listener = TcpListener::bind(addr).await.map_err(|e| {
            error!("failed to bind tunnel access server on address: {addr}, error: {e}");
            e
        })?;

        let addr = tcp_listener.local_addr().unwrap();
        info!("bound tcp server on address: {addr}");

        let (tcp_sender, tcp_receiver) = channel(4);
        let tcp_sender_clone = tcp_sender.clone();

        // unless being explicitly requested, always drop the connections because we are not
        // sure whether the receiver is ready to aceept connections, default is false
        let active = Arc::new(Mutex::new(false));
        let active_clone = active.clone();

        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((socket, addr)) => {
                        if !*active.lock().unwrap() {
                            // silently drop the connection
                            debug!("drop connection: {addr}");
                            continue;
                        }

                        match tcp_sender
                            .send_timeout(
                                Some(ChannelMessage::Request(socket)),
                                Duration::from_millis(100),
                            )
                            .await
                        {
                            Ok(_) => {
                                // succeeded
                            }
                            Err(SendTimeoutError::Timeout(_)) => {
                                debug!("timedout sending the request, drop the socket");
                            }
                            Err(e) => {
                                info!("channel is closed, will quit access server, err:{e}");
                                break;
                            }
                        }
                    }

                    Err(e) => {
                        error!("access server failed, err: {e}");
                    }
                }
            }
        });

        Ok(Self {
            addr,
            tcp_sender: tcp_sender_clone,
            tcp_receiver: Some(tcp_receiver),
            active: active_clone,
        })
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let tcp_receiver = self.tcp_receiver.take();
        // drop the Receiver
        drop(tcp_receiver);

        // initiate a new connection to wake up the accept() loop
        // and make it active so that the sender end of the channel
        // will send a TcpStream to the closed receiver, which causes
        // the entire above loop to quit
        self.set_active(true);
        TcpStream::connect(self.addr).await?;
        Ok(())
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn recv(&mut self) -> Option<ChannelMessage> {
        self.tcp_receiver.as_mut().unwrap().recv().await?
    }

    pub fn clone_tcp_sender(&self) -> Sender<Option<ChannelMessage>> {
        self.tcp_sender.clone()
    }

    pub fn set_active(&self, flag: bool) {
        *self.active.lock().unwrap() = flag;
    }
}
