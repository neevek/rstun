use anyhow::Context;
use anyhow::Result;
use rustls::{Certificate, PrivateKey};
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
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
    if keys.is_empty() {
        let mut reader = BufReader::new(&file);
        keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
    }

    let first_key = keys.first().context("failed to load private key")?;
    Ok(PrivateKey(first_key.to_owned()))
}
