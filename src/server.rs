use crate::{ReadResult, ServerConfig, TunnelType};
use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, error, info, warn};
use quinn::TransportConfig;
use quinn::{Certificate, CertificateChain, PrivateKey, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::Duration;

const IDLE_TIMEOUT: u64 = 30 * 1000;

#[derive(Debug)]
pub struct Server {
    pub config: Arc<ServerConfig>,
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

        let mut transport_cfg = TransportConfig::default();
        transport_cfg
            .max_idle_timeout(Some(Duration::from_millis(IDLE_TIMEOUT)))
            .unwrap();
        transport_cfg.keep_alive_interval(Some(Duration::from_millis(IDLE_TIMEOUT / 2)));
        cfg.transport = Arc::new(transport_cfg);

        cfg.certificate(cert_chain, key)?;
        Arc::get_mut(&mut cfg.transport)
            .unwrap()
            .max_concurrent_bidi_streams(2000)?;

        let mut cfg_builder = quinn::ServerConfigBuilder::new(cfg);
        //cfg_builder.protocols(&[b"\x05rstun"]);
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

        info!("quit!");

        Ok(())
    }

    async fn authenticate_connection(
        connnecing: quinn::Connecting,
        server_config: Arc<ServerConfig>,
        downstream_addrs: Arc<DashMap<String, SocketAddr>>,
    ) -> Result<(quinn::NewConnection, SocketAddr)> {
        let mut conn = connnecing.await?;

        let remote_addr = &conn.connection.remote_address();

        info!(
            "received connection, authenticating... addr:{ }",
            remote_addr
        );

        let mut stream = conn.bi_streams.next().await;
        if stream.is_none() {
            bail!("login request not received in time, addr: {}", remote_addr)
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

            info!("connection authenticated! addr: {}", remote_addr);

            return Ok((conn, downstream_addr.unwrap()));
        }

        bail!("failed to authenticate connection({})", remote_addr)
    }

    async fn handle_connection(
        mut conn: quinn::NewConnection,
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        let remote_addr = &conn.connection.remote_address();

        info!("enter tunnel streaming mode, addr: {}", remote_addr);

        while let Some(stream) = conn.bi_streams.next().await {
            match stream {
                Err(quinn::ConnectionError::TimedOut { .. }) => {
                    info!("connection timeout, addr: {}", remote_addr);
                    return Ok(());
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed, addr: {}", remote_addr);
                    return Ok(());
                }
                Err(e) => {
                    bail!(
                        "failed to open bi_streams, addr: {}, err: {}",
                        remote_addr,
                        e
                    );
                }
                Ok(s) => tokio::spawn(
                    Self::handle_stream(s, downstream_addr)
                        .map_err(|e| debug!("stream ended, err: {}", e)),
                ),
            };
        }

        Ok(())
    }

    async fn handle_stream(
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        info!("received new stream, id: {}", send.id().index());
        if let Ok(mut downstream_conn) = TcpStream::connect(&downstream_addr).await {
            let mut up_read_result = ReadResult::Succeeded;
            loop {
                let (mut down_read, mut down_write) = downstream_conn.split();
                let up2down = Self::upstream_to_downstream(&mut recv, &mut down_write);
                let down2up = Self::downstream_to_upstream(&mut down_read, &mut send);
                tokio::select! {
                    Ok(result) = up2down, if !up_read_result.is_eof() => {
                        up_read_result = result;
                    }
                    Ok(result) = down2up => {
                        if let ReadResult::EOF = result {
                            info!("quit stream after hitting EOF, stream_id: {}", send.id().index());
                            break;
                        }
                    }
                    else => {
                        info!("quit unexpectedly, stream_id: {}", send.id().index());
                        break;
                    }
                };
            }
        }

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
    ) -> Result<ReadResult> {
        let mut buffer = vec![0_u8; 8192];
        let len_read = down_read.read(&mut buffer[..]).await?;

        if len_read > 0 {
            up_send.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            Ok(ReadResult::EOF)
        }
    }

    async fn upstream_to_downstream<'a>(
        up_recv: &'a mut RecvStream,
        down_write: &'a mut WriteHalf<'a>,
    ) -> Result<ReadResult> {
        let mut buffer = vec![0_u8; 8192];
        let result = up_recv.read(&mut buffer[..]).await?;
        if let Some(len_read) = result {
            down_write.write_all(&buffer[..len_read]).await?;
            return Ok(ReadResult::Succeeded);
        }
        return Ok(ReadResult::EOF);
    }

    fn read_cert_and_key(cert_path: &str, key_path: &str) -> Result<(Certificate, PrivateKey)> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let key = std::fs::read(key_path).context("failed to read key file")?;
        let cert = Certificate::from_pem(&cert[..]).context("failed to create Certificate")?;
        let key = PrivateKey::from_pem(&key[..]).context("failed to create PrivateKey")?;

        Ok((cert, key))
    }
}
