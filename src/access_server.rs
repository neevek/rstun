use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[derive(Debug)]
pub struct AccessServer {
    addr: String,
    tcp_listener: Option<Arc<TcpListener>>,
    tcp_sender: Sender<TcpStream>,
    tcp_receiver: Receiver<TcpStream>,
    pub running: bool,
}

impl AccessServer {
    pub fn new(addr: String) -> Self {
        let (sender, receiver) = channel(50000);

        AccessServer {
            addr,
            tcp_listener: None,
            tcp_sender: sender,
            tcp_receiver: receiver,
            running: false,
        }
    }

    pub async fn bind(&mut self) -> Result<()> {
        let addr: SocketAddr = self
            .addr
            .parse()
            .with_context(|| format!("invalid address: {}", self.addr))?;

        let tcp_listener = TcpListener::bind(addr)
            .await
            .context("failed to start AccessServer")?;

        self.tcp_listener = Some(Arc::new(tcp_listener));
        self.running = true;

        info!("started access server: {}", addr);

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
                        tcp_sender
                            .send(socket)
                            .await
                            .map_err(|e| {
                                error!("failed to send connection over channel, err: {}", e);
                            })
                            .unwrap();
                    }
                    Err(e) => {
                        error!("access server failed, err: {}", e);
                    }
                }
            }
        });
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn tcp_receiver(&mut self) -> &mut Receiver<TcpStream> {
        &mut self.tcp_receiver
    }
}
