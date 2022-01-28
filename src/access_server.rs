use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[derive(Debug)]
pub struct AccessServer {
    addr: SocketAddr,
    tcp_listener: Option<Arc<TcpListener>>,
    tcp_sender: Sender<Option<TcpStream>>,
    take_tcp_receiver: Option<Receiver<Option<TcpStream>>>,
}

impl AccessServer {
    pub fn new(addr: SocketAddr) -> Self {
        let (sender, receiver) = channel(50000);

        AccessServer {
            addr,
            tcp_listener: None,
            tcp_sender: sender,
            take_tcp_receiver: Some(receiver),
        }
    }

    pub async fn bind(&mut self) -> Result<()> {
        info!("staring access server... addr: {}", self.addr);

        let tcp_listener = TcpListener::bind(self.addr)
            .await
            .context("failed to start AccessServer")?;

        self.tcp_listener = Some(Arc::new(tcp_listener));

        info!("started access server: {}", self.addr);

        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.tcp_listener.is_none() {
            bail!("bind the server first");
        }

        let listener = self.tcp_listener.clone().unwrap();
        let tcp_sender = self.tcp_sender.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        debug!("received new local connection, addr: {}", addr);
                        if tcp_sender
                            .send(Some(socket))
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

    pub async fn shutdown(&self, tcp_receiver: Receiver<Option<TcpStream>>) -> Result<()> {
        // drop the Receiver
        drop(tcp_receiver);

        // initiate a new connection to wake up the accept() loop
        TcpStream::connect(self.addr).await?;
        Ok(())
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn take_tcp_receiver(&mut self) -> Receiver<Option<TcpStream>> {
        self.take_tcp_receiver.take().unwrap()
    }

    pub fn clone_tcp_sender(&mut self) -> Sender<Option<TcpStream>> {
        self.tcp_sender.clone()
    }
}
