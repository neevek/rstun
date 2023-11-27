use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::Item;
use std::{fs::File, io::BufReader};

pub fn load_certificates_from_pem(path: &str) -> Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;
    Ok(certs.into_iter().map(Certificate).collect())
}

pub fn load_private_key_from_pem(path: &str) -> Result<PrivateKey> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(&file);

    let key = match rustls_pemfile::read_one(&mut reader).context("failed to read private key")? {
        Some(Item::RSAKey(key)) => key,
        Some(Item::PKCS8Key(key)) => key,
        Some(Item::ECKey(key)) => key,
        _ => bail!("unexpected private key"),
    };

    Ok(PrivateKey(key.to_owned()))
}
