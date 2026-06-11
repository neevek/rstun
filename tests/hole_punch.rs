//! Loopback self-punch test for the `Puncher` simultaneous-open state machine.
//!
//! Two punchers on loopback (no real NAT) validate the dual-role endpoint:
//! one dials, one accepts, concurrently; a connection forms and carries bytes.
//! mTLS identity is the embedder's concern — here a self-signed cert + an
//! accept-any verifier exercise only the punch mechanics.

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rstun::{PunchRole, Puncher};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn punch_configs() -> (quinn::ClientConfig, quinn::ServerConfig) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);

    let server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key))
        .unwrap();
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).unwrap(),
    ));

    let client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    let client_cfg =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    (client_cfg, server_cfg)
}

#[tokio::test]
async fn loopback_simultaneous_open_punches_and_carries_bytes() {
    let (ca, sa) = punch_configs();
    let (cb, sb) = punch_configs();
    let a = Puncher::bind("127.0.0.1:0".parse().unwrap(), ca, sa).expect("bind A");
    let b = Puncher::bind("127.0.0.1:0".parse().unwrap(), cb, sb).expect("bind B");
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();

    let t = Duration::from_secs(5);
    // Simultaneous open: A dials B, B accepts A — concurrently.
    let (ra, rb) = tokio::join!(
        a.punch(b_addr, "localhost", PunchRole::Dial, t),
        b.punch(a_addr, "localhost", PunchRole::Accept, t),
    );
    let conn_a = ra.expect("A punch should succeed");
    let conn_b = rb.expect("B punch should succeed");

    // The punched connection carries an application bidi stream.
    let (mut send, _r) = conn_a.open_bi().await.expect("A open_bi");
    send.write_all(b"punched").await.expect("write");
    send.finish().ok();

    let (mut _s, mut recv) = conn_b.accept_bi().await.expect("B accept_bi");
    let mut buf = [0u8; 7];
    recv.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"punched");
}
