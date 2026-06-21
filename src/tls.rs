//! Self-signed certificate generation and key file writing.
use std::path::Path;

#[derive(Debug)]
pub enum TlsError {
    Gen(String),
}

pub fn generate_self_signed(hostnames: &[String]) -> Result<(String, String), TlsError> {
    let cert = rcgen::generate_simple_self_signed(hostnames.to_vec())
        .map_err(|e| TlsError::Gen(e.to_string()))?;
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

pub fn write_cert_files(
    cert_pem: &str,
    key_pem: &str,
    cert_path: &Path,
    key_path: &Path,
) -> std::io::Result<()> {
    // Cert may be world-readable.
    std::fs::write(cert_path, cert_pem)?;

    // Private key: create with 0600 from the start (no world-readable window).
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(key_path)?;
        f.write_all(key_pem.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(key_path, key_pem)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gencert_produces_pem() {
        let (cert, key) = generate_self_signed(&["reoftpd.local".to_string()]).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
    }

    #[test]
    fn write_cert_files_creates_files_with_correct_permissions() {
        let (cert, key) = generate_self_signed(&["reoftpd.local".to_string()]).unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        write_cert_files(&cert, &key, &cert_path, &key_path).expect("write_cert_files");
        assert!(cert_path.exists());
        assert!(key_path.exists());
        let cert_contents = std::fs::read_to_string(&cert_path).unwrap();
        let key_contents = std::fs::read_to_string(&key_path).unwrap();
        assert!(cert_contents.contains("BEGIN CERTIFICATE"));
        assert!(key_contents.contains("PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&key_path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
}
