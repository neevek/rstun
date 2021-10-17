use crate::ServerConfig;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use log::{debug, info};
use quinn::{Certificate, CertificateChain, PrivateKey};
use std::sync::Arc;

#[derive(Debug)]
pub struct Server {
    pub config: ServerConfig,
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

        while let Some(conn) = incoming.next().await {
            tokio::spawn(Self::handle_connection(conn));
        }

        Ok(())
    }

    async fn handle_connection(connnecing: quinn::Connecting) -> Result<()> {
        let quinn::NewConnection {
            connection,
            mut bi_streams,
            ..
        } = connnecing.await?;

        info!("new connection, addr: {}", connection.remote_address());

        async {
            while let Some(stream) = bi_streams.next().await {
                match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        debug!("connection closed, addr: {}", connection.remote_address());
                        return Ok(());
                    }
                    Err(e) => {
                        debug!("handle_connection failed: {}", e);
                        return Err(e);
                    }
                    Ok(s) => tokio::spawn(Self::handle_stream(s)),
                };
            }
            Ok(())
        }
        .await?;

        Ok(())
    }

    async fn handle_stream((mut send, recv): (quinn::SendStream, quinn::RecvStream)) -> Result<()> {
        let buf = recv.read_to_end(64 * 1024).await?;
        let s = String::from_utf8(buf);
        debug!("from client: {}", s.unwrap());

        send.write_all(b"hello from server").await?;
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
