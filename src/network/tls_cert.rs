//! Gestión de certificado TLS autofirmado persistente y huella SHA-256 para QR pinning
//! en el servidor TCP local (puerto 45362) y Wi-Fi Direct (Fase D1).

use anyhow::Context;
use ring::digest::{digest, SHA256};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub struct LocalTlsIdentity {
    pub acceptor: TlsAcceptor,
    pub cert_sha256_hex: String,
}

fn sha256_lower_hex(der: &[u8]) -> String {
    let d = digest(&SHA256, der);
    let mut out = String::with_capacity(64);
    for b in d.as_ref() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn build_acceptor(cert_der: Vec<u8>, key_der: Vec<u8>) -> anyhow::Result<LocalTlsIdentity> {
    let cert_sha256_hex = sha256_lower_hex(&cert_der);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("protocolos TLS inválidos")?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .context("certificado o llave privada TLS inválidos")?;

    Ok(LocalTlsIdentity {
        acceptor: TlsAcceptor::from(Arc::new(server_cfg)),
        cert_sha256_hex,
    })
}

pub fn load_or_create_default() -> anyhow::Result<LocalTlsIdentity> {
    let dir = PathBuf::from(
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()),
    )
    .join("NFC Bridge");
    load_or_create_in_dir(&dir)
}

pub fn load_or_create_in_dir(data_dir: &Path) -> anyhow::Result<LocalTlsIdentity> {
    let cert_path = data_dir.join("tcp_tls_cert.der");
    let key_path = data_dir.join("tcp_tls_key.der");

    if let (Ok(cert_der), Ok(key_der)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        if !cert_der.is_empty() && !key_der.is_empty() {
            if let Ok(identity) = build_acceptor(cert_der, key_der) {
                return Ok(identity);
            }
        }
    }

    let certified = rcgen::generate_simple_self_signed(vec![
        "nfc-bridge.local".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .context("no se pudo generar certificado TLS autofirmado")?;

    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    if std::fs::create_dir_all(data_dir).is_ok() {
        let _ = std::fs::write(&cert_path, &cert_der);
        let _ = std::fs::write(&key_path, &key_der);
    }

    build_acceptor(cert_der, key_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create_persists_sha256_fingerprint() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("nfc_bridge_tls_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let id1 = load_or_create_in_dir(&dir).expect("primera creación TLS");
        assert_eq!(id1.cert_sha256_hex.len(), 64);

        let id2 = load_or_create_in_dir(&dir).expect("recarga TLS persistida");
        assert_eq!(id1.cert_sha256_hex, id2.cert_sha256_hex);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
