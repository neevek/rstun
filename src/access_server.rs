use anyhow::{bail, Result};
use log::{debug, error, info};
use rs_utilities::log_and_bail;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub enum ChannelMessage {
    Request(TcpStream),
    Reconnect,
}

#[derive(Debug)]
pub struct AccessServer {
    addr: SocketAddr,
    tcp_listener: Option<Arc<TcpListener>>,
    tcp_sender: Sender<Option<ChannelMessage>>,
    tcp_receiver: Option<Receiver<Option<ChannelMessage>>>,
}

impl AccessServer {
    pub fn new(addr: SocketAddr) -> Self {
        let (sender, receiver) = channel(1024);

        AccessServer {
            addr,
            tcp_listener: None,
            tcp_sender: sender,
            tcp_receiver: Some(receiver),
        }
    }

    pub async fn bind(&mut self) -> Result<SocketAddr> {
        info!("starting access server, addr: {}", self.addr);
        let tcp_listener = TcpListener::bind(self.addr).await.map_err(|e| {
            error!(
                "failed to bind tunnel access server on address: {}, error: {}",
                self.addr, e
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
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        debug!("received new local connection, addr: {}", addr);
                        if tcp_sender
                            .send(Some(ChannelMessage::Request(socket)))
                            .await
                            .map_err(|e| {
                                error!("failed to send connection over channel, err: {}", e);
                            })
                            .is_err()
                        {
                            info!("channel is closed, will quit access server");
                            break;
                        }
                    }

                    Err(e) => {
                        error!("access server failed, err: {}", e);
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
}
