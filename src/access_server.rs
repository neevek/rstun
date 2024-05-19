use anyhow::{bail, Result};
use log::{debug, error, info};
use rs_utilities::log_and_bail;
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
pub struct AccessServer {
    addr: SocketAddr,
    tcp_listener: Option<Arc<TcpListener>>,
    tcp_sender: Sender<Option<ChannelMessage>>,
    tcp_receiver: Option<Receiver<Option<ChannelMessage>>>,
    drop_conn: Arc<Mutex<bool>>,
}

impl AccessServer {
    pub fn new(addr: SocketAddr) -> Self {
        let (sender, receiver) = channel(4);

        AccessServer {
            addr,
            tcp_listener: None,
            tcp_sender: sender,
            tcp_receiver: Some(receiver),
            // unless being explicitly requested, always drop the connections because we are not
            // sure whether the receiver is ready to aceept connections
            drop_conn: Arc::new(Mutex::new(true)),
        }
    }

    pub async fn bind(&mut self) -> Result<SocketAddr> {
        info!("starting access server, addr: {}", self.addr);
        let tcp_listener = TcpListener::bind(self.addr).await.map_err(|e| {
            error!(
                "failed to bind tunnel access server on address: {}, error: {e}",
                self.addr
            );
            e
        })?;

        let bound_addr = tcp_listener.local_addr().unwrap();
        self.tcp_listener = Some(Arc::new(tcp_listener));
        info!("bound tunnel access server on address: {}", self.addr);

        Ok(bound_addr)
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.tcp_listener.is_none() {
            log_and_bail!("bind the server first");
        }

        let listener = self.tcp_listener.clone().unwrap();
        let tcp_sender = self.tcp_sender.clone();
        let drop_conn = self.drop_conn.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        if *drop_conn.lock().unwrap() {
                            // silently drop the connection
                            debug!("drop connection: {addr}");
                            continue;
                        }

                        debug!("received conn :       {addr}");
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
        Ok(())
    }

    pub async fn shutdown(&self, tcp_receiver: Receiver<Option<ChannelMessage>>) -> Result<()> {
        // drop the Receiver
        drop(tcp_receiver);

        // initiate a new connection to wake up the accept() loop
        self.set_drop_conn(false);
        TcpStream::connect(self.addr).await?;
        Ok(())
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub async fn recv(&mut self) -> Option<ChannelMessage> {
        self.tcp_receiver.as_mut().unwrap().recv().await?
    }

    pub fn take_tcp_receiver(&mut self) -> Receiver<Option<ChannelMessage>> {
        self.tcp_receiver.take().unwrap()
    }

    pub fn clone_tcp_sender(&self) -> Sender<Option<ChannelMessage>> {
        self.tcp_sender.clone()
    }

    pub fn set_drop_conn(&self, flag: bool) {
        *self.drop_conn.lock().unwrap() = flag;
    }
}
