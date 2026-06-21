//! argon2id password hashing producing PHC strings.
use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use password_hash::rand_core::OsRng;

#[derive(Debug)]
pub enum HashError {
    Hash(String),
    Parse(String),
}

fn hasher() -> Argon2<'static> {
    // OWASP argon2id params: m=19456 KiB, t=2, p=1.
    let params = Params::new(19456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(plain: &str) -> Result<String, HashError> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = hasher()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| HashError::Hash(e.to_string()))?;
    Ok(phc.to_string())
}

pub fn verify_password(plain: &str, phc: &str) -> Result<bool, HashError> {
    let parsed = PasswordHash::new(phc).map_err(|e| HashError::Parse(e.to_string()))?;
    Ok(hasher().verify_password(plain.as_bytes(), &parsed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrip() {
        let phc = hash_password("s3cret-cam-pw").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("s3cret-cam-pw", &phc).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let phc = hash_password("right").unwrap();
        assert!(!verify_password("wrong", &phc).unwrap());
    }

    #[test]
    fn malformed_hash_errors() {
        assert!(verify_password("x", "not-a-phc-string").is_err());
    }
}
