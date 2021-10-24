use anyhow::{bail, Context, Result};
use log::{error, info};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;

pub struct AccessServer {
    addr: String,
    tcp_listener: Option<TcpListener>,
}

impl AccessServer {
    pub fn new(addr: String) -> Self {
        AccessServer {
            addr,
            tcp_listener: None,
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

        self.tcp_listener = Some(tcp_listener);

        info!("started access server: {}", addr);

        Ok(())
    }

    pub async fn start(&mut self, conn_sender: Sender<TcpStream>) -> Result<()> {
        if self.tcp_listener.is_none() {
            bail!("bind the server first");
        }

        let listener = self.tcp_listener.take().unwrap();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, _addr)) => {
                        conn_sender
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
}
