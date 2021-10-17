use crate::{ClientConfig, ForwardLoginInfo, TunnelType};
use anyhow::{Context, Result};
use log::{debug, error, info};
use quinn::crypto::rustls::TLSError;
use quinn::Certificate;
use rustls::ServerCertVerified;
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

const LOCAL_ADDR_STR: &str = "0.0.0.0:0";

pub struct Client {
    pub config: ClientConfig,
}

impl Client {
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let mut cfg = quinn::ClientConfig::default();

        info!("using cert: {}", config.cert_path);

        let cert = Client::read_cert(config.cert_path.as_str())?;
        let tls_cfg = Arc::get_mut(&mut cfg.crypto).unwrap();
        tls_cfg
            .dangerous()
            .set_certificate_verifier(Arc::new(CertVerifier { cert: cert.clone() }));

        let mut cfg_builder = quinn::ClientConfigBuilder::new(cfg);
        cfg_builder.add_certificate_authority(cert)?;
        cfg_builder.protocols(&[b"\x05rstun"]);
        cfg_builder.enable_keylog();

        let remote_addr = config
            .addr
            .parse()
            .with_context(|| format!("invalid address: {}", config.addr))?;

        let local_addr = LOCAL_ADDR_STR
            .parse()
            .with_context(|| format!("invalid address: {}", config.addr))?;

        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.default_client_config(cfg_builder.build());

        let (endpoint, _) = endpoint_builder.bind(&local_addr)?;

        info!(
            "connecting to {}, local_addr: {}",
            remote_addr,
            endpoint.local_addr().unwrap()
        );

        let quinn::NewConnection { connection, .. } = endpoint
            .connect(&remote_addr, "localhost")?
            .await
            .context("connect failed!")?;

        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| error!("open bidirectional connection failed: {}", e))
            .unwrap();

        let tun_type = TunnelType::Forward(ForwardLoginInfo {
            password: "hello world!".to_string(),
            remote_downstream_name: "http".to_string(),
        });

        let tun_type = bincode::serialize(&tun_type).unwrap();
        send.write_u16(tun_type.len() as u16).await?;
        send.write_all(&tun_type).await?;

        let buf = recv
            .read_to_end(usize::max_value())
            .await
            .context("read failed")?;

        let s = String::from_utf8(buf);
        debug!("from server: {}", s.unwrap());

        Ok(Client { config })
    }

    fn read_cert(cert_path: &str) -> Result<Certificate> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let cert = Certificate::from_pem(&cert[..]).context("failed to create Certificate")?;

        Ok(cert)
    }
}

struct CertVerifier {
    cert: Certificate,
}

impl rustls::ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::RootCertStore,
        presented_certs: &[rustls::Certificate],
        _: webpki::DNSNameRef,
        _: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        if presented_certs.len() != 1 {
            return Err(TLSError::General(format!(
                "server sent {} certificates, expected one",
                presented_certs.len()
            )));
        }
        if presented_certs[0].0 != self.cert.as_der() {
            return Err(TLSError::General(format!(
                "server certificates doesn't match ours"
            )));
        }

        info!("pass!");
        Ok(ServerCertVerified::assertion())
    }
}
