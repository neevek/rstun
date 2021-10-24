use crate::{ServerConfig, TunnelType};
use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, error, info, warn};
use quinn::{Certificate, CertificateChain, PrivateKey, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::Duration;

#[derive(Debug)]
pub struct Server {
    pub config: Arc<ServerConfig>,
}

struct Session {
    downstream: TcpStream,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Server {
            config: Arc::new(config),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let config = &self.config;
        let (cert, key) =
            match Server::read_cert_and_key(config.cert_path.as_str(), config.key_path.as_str()) {
                Ok(v) => v,
                Err(_) => {
                    info!("generate temporary cert and key");
                    let cert =
                        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let key = cert.serialize_private_key_pem();
                    let cert = cert.serialize_pem().unwrap();
                    let cert = Certificate::from_pem(cert.as_bytes()).unwrap();
                    let key = PrivateKey::from_pem(key.as_bytes()).unwrap();
                    (cert, key)
                }
            };

        let cert_chain = CertificateChain::from_certs(vec![cert]);
        let mut cfg = quinn::ServerConfig::default();
        cfg.certificate(cert_chain, key)?;
        Arc::get_mut(&mut cfg.transport)
            .unwrap()
            .max_concurrent_bidi_streams(2000)?;

        let mut cfg_builder = quinn::ServerConfigBuilder::new(cfg);
        cfg_builder.protocols(&[b"\x05rstun"]);
        cfg_builder.use_stateless_retry(true);
        cfg_builder.enable_keylog();

        let addr = config
            .addr
            .parse()
            .with_context(|| format!("invalid address: {}", config.addr))?;

        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.listen(cfg_builder.build());
        let (endpoint, mut incoming) = endpoint_builder.bind(&addr)?;
        info!("server is bound to: {}", endpoint.local_addr()?);

        let downstream_addrs: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
        for (name, str_addr) in &self.config.downstreams {
            if let Ok(addr) = str_addr.parse() {
                downstream_addrs.insert(name.clone(), addr);
            } else {
                warn!("failed to parse downstream address: {}", str_addr);
            }
        }

        while let Some(conn) = incoming.next().await {
            let server_config = self.config.clone();
            let downstream_addrs = downstream_addrs.clone();
            tokio::spawn(async move {
                if let Ok((conn, addr)) =
                    Self::authenticate_connection(conn, server_config, downstream_addrs).await
                {
                    Self::handle_connection(conn, addr)
                        .await
                        .map_err(|e| error!("handle_connection failed: {}", e))
                        .ok();
                }
            });
        }

        Ok(())
    }

    async fn authenticate_connection(
        connnecing: quinn::Connecting,
        server_config: Arc<ServerConfig>,
        downstream_addrs: Arc<DashMap<String, SocketAddr>>,
    ) -> Result<(quinn::NewConnection, SocketAddr)> {
        let mut conn = connnecing.await?;

        info!(
            "authenticating connection({})...",
            conn.connection.remote_address()
        );

        let mut stream = conn.bi_streams.next().await;
        if stream.is_none() {
            bail!(
                "login request not received in time from addr: {}",
                conn.connection.remote_address()
            )
        }

        if let Ok((mut send, mut recv)) = stream.take().unwrap() {
            let mut login_info_len = [0_u8; 2];
            recv.read_exact(&mut login_info_len)
                .await
                .context("read login_info_len failed")?;

            let login_info_len = ((login_info_len[0] as usize) << 8) | (login_info_len[1] as usize);
            let mut login_info = vec![0; login_info_len];
            recv.read_exact(&mut login_info)
                .await
                .context("read login_info failed")?;

            let tun_type = bincode::deserialize::<TunnelType>(&login_info)?;

            let mut downstream_addr = None;
            match tun_type {
                TunnelType::Forward(i) => {
                    Self::check_password(server_config.password.as_str(), i.password.as_str())?;

                    if downstream_addrs.contains_key(i.remote_downstream_name.as_str()) {
                        downstream_addr = Some(
                            *downstream_addrs
                                .get(i.remote_downstream_name.as_str())
                                .unwrap()
                                .value(),
                        );
                        send.write_all(b"ok").await?;
                    } else {
                        send.write_all(b"downstream_name not found").await?;
                    }
                }
                TunnelType::Reverse(i) => {
                    Self::check_password(server_config.password.as_str(), i.password.as_str())?;
                    send.write_all(b"ok").await?;
                }
            }

            if downstream_addr.is_none() {
                bail!("downstream_name not found");
            }

            tokio::spawn(async move {
                let heartbeat_out = [0_u8; 1];
                let mut heartbeat_in = [0_u8; 1];
                let mut fail_count = 0;
                let exchange_heartbeat_interval: Duration = Duration::from_secs(5);
                loop {
                    tokio::time::sleep(exchange_heartbeat_interval).await;
                    tokio::select! {
                        Ok(_) = send.write_all(&heartbeat_out) => {}
                        Ok(_) = recv.read(&mut heartbeat_in) => {}
                        else => {
                            fail_count += 1;
                            if fail_count > 10 {
                                break;
                            }
                        }
                    }
                }
            });

            info!(
                "authenticated connection({})",
                conn.connection.remote_address()
            );

            return Ok((conn, downstream_addr.unwrap()));
        }

        bail!(
            "failed to authenticate connection({})",
            conn.connection.remote_address()
        )
    }

    async fn handle_connection(
        mut conn: quinn::NewConnection,
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        info!(
            "enter tunnel streaming with remote: {}",
            conn.connection.remote_address()
        );

        while let Some(stream) = conn.bi_streams.next().await {
            match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!(
                        "connection closed, addr: {}",
                        conn.connection.remote_address()
                    );
                    return Ok(());
                }
                Err(e) => {
                    bail!(
                        "failed to open streams on connection({}), err: {}",
                        conn.connection.remote_address(),
                        e
                    );
                }
                Ok(s) => tokio::spawn(
                    Self::handle_stream(s, downstream_addr).map_err(|e| error!("{}", e)),
                ),
            };
        }

        Ok(())
    }

    async fn handle_stream(
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        if let Ok(mut downstream_conn) = TcpStream::connect(&downstream_addr).await {
            loop {
                let (mut down_read, mut down_write) = downstream_conn.split();
                tokio::select! {
                    result =  Self::upstream_to_downstream(&mut recv, &mut down_write) => {
                        if let Err(e) = result {
                            debug!("upstream_to_downstream failed, err: {}", e);
                            break;
                        }
                    }
                    result = Self::downstream_to_upstream(&mut down_read, &mut send) => {
                        if let Err(e) = result {
                            debug!("downstream_to_upstream failed, err: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        send.finish().await?;
        Ok(())
    }

    fn check_password(password1: &str, password2: &str) -> Result<()> {
        if password1 != password2 {
            bail!("passwords don't match!");
        }
        Ok(())
    }

    async fn downstream_to_upstream<'a>(
        down_read: &'a mut ReadHalf<'a>,
        up_send: &'a mut SendStream,
    ) -> Result<()> {
        let mut buffer = vec![0_u8; 8192];
        down_read.read(&mut buffer[..]).await?;
        up_send.write_all(&buffer).await?;
        Ok(())
    }

    async fn upstream_to_downstream<'a>(
        up_recv: &'a mut RecvStream,
        down_write: &'a mut WriteHalf<'a>,
    ) -> Result<()> {
        let mut buffer = vec![0_u8; 8192];
        up_recv.read(&mut buffer[..]).await?;
        down_write.write_all(&buffer).await?;
        Ok(())
    }

    fn read_cert_and_key(cert_path: &str, key_path: &str) -> Result<(Certificate, PrivateKey)> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let key = std::fs::read(key_path).context("failed to read key file")?;
        let cert = Certificate::from_pem(&cert[..]).context("failed to create Certificate")?;
        let key = PrivateKey::from_pem(&key[..]).context("failed to create PrivateKey")?;

        Ok((cert, key))
    }
}
