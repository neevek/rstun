use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls_pemfile::Item;
use std::fs;
use std::path::PathBuf;
use std::{fs::File, io::BufReader};

pub fn load_certificates_from_pem(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file_path = PathBuf::from(path);
    let cert_buf = fs::read(file_path).context("reading cert failed")?;
    let cert_buf = &mut cert_buf.as_ref();
    let certs = rustls_pemfile::certs(cert_buf);
    Ok(certs.filter_map(Result::ok).collect())
}

pub fn load_private_key_from_pem(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(&file);

    let key = match rustls_pemfile::read_one(&mut reader).context("failed to read private key")? {
        Some(Item::Pkcs1Key(key)) => PrivateKeyDer::Pkcs1(key),
        Some(Item::Pkcs8Key(key)) => PrivateKeyDer::Pkcs8(key),
        Some(Item::Sec1Key(key)) => PrivateKeyDer::Sec1(key),
        _ => bail!("unexpected private key"),
    };

    Ok(key)
}
