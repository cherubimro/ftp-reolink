//! age (X25519) encryption-at-rest helpers. Pure, synchronous, unit-tested.
//! The async backend bridges to these via tokio_util::io::SyncIoBridge.
use std::io::{Read, Write};
use std::str::FromStr;

use age::secrecy::ExposeSecret as _;

#[derive(Debug)]
pub enum CryptoError {
    Recipient(String),
    Identity(String),
    Encrypt(String),
    Decrypt(String),
    Io(std::io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Recipient(e) => write!(f, "invalid age recipient: {e}"),
            CryptoError::Identity(e) => write!(f, "invalid age identity: {e}"),
            CryptoError::Encrypt(e) => write!(f, "encryption failed: {e}"),
            CryptoError::Decrypt(e) => write!(f, "decryption failed: {e}"),
            CryptoError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::Io(e)
    }
}

/// Parse a slice of public key strings (bech32 "age1...") into age recipients.
pub fn parse_recipients(strs: &[String]) -> Result<Vec<age::x25519::Recipient>, CryptoError> {
    strs.iter()
        .map(|s| {
            age::x25519::Recipient::from_str(s.trim())
                .map_err(|e| CryptoError::Recipient(format!("{s}: {e}")))
        })
        .collect()
}

/// Generate a new X25519 keypair.
///
/// Returns `(public_recipient, secret_identity)` where:
/// - `public_recipient` is the bech32 "age1..." string
/// - `secret_identity` is the bech32 "AGE-SECRET-KEY-..." string
///
/// Note: `age::x25519::Identity::to_string()` returns a `SecretString` (from the
/// `secrecy` crate) rather than a plain `String`. We call `.expose_secret()` to obtain
/// the underlying string and clone it into a plain `String` for the caller.
pub fn generate_identity() -> (String, String) {
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();
    // to_string() returns SecretString; expose_secret() yields &str
    let secret = id.to_string().expose_secret().to_string();
    (public, secret)
}

/// Encrypt bytes from `reader` to all `recipients`, writing ciphertext to `writer`.
///
/// Returns the number of plaintext bytes processed.
pub fn encrypt_stream<R: Read, W: Write>(
    recipients: &[age::x25519::Recipient],
    mut reader: R,
    writer: W,
) -> Result<u64, CryptoError> {
    let recs = recipients.iter().map(|r| r as &dyn age::Recipient);
    let encryptor =
        age::Encryptor::with_recipients(recs).map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    // wrap_output returns io::Result<StreamWriter<W>>
    let mut stream_writer = encryptor
        .wrap_output(writer)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    let n = std::io::copy(&mut reader, &mut stream_writer)?;
    // finish() flushes the final age chunk and returns the inner writer
    let mut inner = stream_writer
        .finish()
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    inner.flush()?;
    Ok(n)
}

/// Decrypt ciphertext from `reader` using `identity`, writing plaintext to `writer`.
///
/// Returns the number of plaintext bytes written.
pub fn decrypt_stream<R: Read, W: Write>(
    identity: &age::x25519::Identity,
    reader: R,
    mut writer: W,
) -> Result<u64, CryptoError> {
    let decryptor = age::Decryptor::new(reader).map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let mut stream_reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let n = std::io::copy(&mut stream_reader, &mut writer)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn round_trip_single_recipient() {
        let (pubkey, secret) = generate_identity();
        let recips = parse_recipients(&[pubkey]).unwrap();
        let plaintext = b"top secret footage";
        let mut ct = Vec::new();
        let n = encrypt_stream(&recips, &plaintext[..], &mut ct).unwrap();
        assert_eq!(n, plaintext.len() as u64);
        assert_ne!(ct.as_slice(), &plaintext[..]); // it's ciphertext
        let id = age::x25519::Identity::from_str(&secret).unwrap();
        let mut pt = Vec::new();
        decrypt_stream(&id, &ct[..], &mut pt).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn multi_recipient_each_can_decrypt() {
        let (p1, s1) = generate_identity();
        let (p2, s2) = generate_identity();
        let recips = parse_recipients(&[p1, p2]).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(&recips, &b"x"[..], &mut ct).unwrap();
        for s in [s1, s2] {
            let id = age::x25519::Identity::from_str(&s).unwrap();
            let mut pt = Vec::new();
            decrypt_stream(&id, &ct[..], &mut pt).unwrap();
            assert_eq!(pt, b"x");
        }
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_recipients(&["not-an-age-key".to_string()]).is_err());
        // a valid-looking key parses:
        let (pubkey, _) = generate_identity();
        assert_eq!(parse_recipients(&[pubkey]).unwrap().len(), 1);
    }
}
