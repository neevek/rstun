use crate::{ServerConfig, TunnelType};
use anyhow::{Context, Result};
use dashmap::DashMap;
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, error, info, warn};
use quinn::{Certificate, CertificateChain, PrivateKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct Server {
    pub config: ServerConfig,
}

struct Session {
    downstream: TcpStream,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Server { config }
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
            tokio::spawn(
                Self::handle_connection(conn, downstream_addrs.clone())
                    .map_err(|e| error!("{}", e)),
            );
        }

        Ok(())
    }

    async fn handle_connection(
        connnecing: quinn::Connecting,
        downstream_addrs: Arc<DashMap<String, SocketAddr>>,
    ) -> Result<()> {
        let quinn::NewConnection {
            connection,
            mut bi_streams,
            ..
        } = connnecing.await?;

        info!("new connection, addr: {}", connection.remote_address());

        //let downstream_map: DashMap<usize, >  = DashMap::new();

        async {
            while let Some(stream) = bi_streams.next().await {
                match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        debug!("connection closed, addr: {}", connection.remote_address());
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(s) => tokio::spawn(
                        Self::handle_stream(s, downstream_addrs.clone())
                            .map_err(|e| error!("{}", e)),
                    ),
                };
            }
            Ok(())
        }
        .await?;

        Ok(())
    }

    async fn handle_stream(
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        downstream_addrs: Arc<DashMap<String, SocketAddr>>,
    ) -> Result<()> {
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

        match tun_type {
            TunnelType::Forward(i) => {
                debug!("password: {}", i.password);
                send.write_all(b"ok").await?;
            }
            TunnelType::Reverse(i) => {
                debug!("password: {}", i.password);
                send.write_all(b"ok").await?;
            }
        }

        send.finish().await?;
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
