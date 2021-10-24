use anyhow::{bail, Context, Result};
use log::{error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub struct AccessServer {
    addr: String,
    tcp_listener: Option<Arc<TcpListener>>,
    tcp_sender: Sender<TcpStream>,
    tcp_receiver: Receiver<TcpStream>,
    pub running: bool,
}

impl AccessServer {
    pub fn new(addr: String) -> Self {
        let (sender, receiver) = channel(500);

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

        info!("started access server: {}", addr);

        self.running = true;

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
                    Ok((socket, _addr)) => {
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
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn tcp_receiver(&mut self) -> &mut Receiver<TcpStream> {
        &mut self.tcp_receiver
    }
}
