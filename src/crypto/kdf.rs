use super::{CryptoError, Key32};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: 65536,
            t: 3,
            p: 1,
        }
    }
}

pub const INFO_RECOVERY: &str = "pm/v1/kek/recovery";
pub const INFO_TOKEN: &str = "pm/v1/kek/token";

/// Derive a KEK from a password with Argon2id.
pub fn password_kek(
    password: &str,
    salt: &[u8; 16],
    p: &Argon2Params,
) -> Result<Key32, CryptoError> {
    let params = argon2::Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| CryptoError::Kdf)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(Key32::from_bytes(*out))
}

/// Derive a KEK from a high-entropy secret with HKDF-SHA256 (no salt).
pub fn secret_kek(secret: &[u8; 32], info: &str) -> Key32 {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, secret);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    Key32::from_bytes(*out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Argon2Params = Argon2Params {
        m_kib: 1024,
        t: 1,
        p: 1,
    };

    #[test]
    fn password_kek_deterministic_and_salt_sensitive() {
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let a = password_kek("pw", &s1, &FAST).unwrap();
        let b = password_kek("pw", &s1, &FAST).unwrap();
        let c = password_kek("pw", &s2, &FAST).unwrap();
        let d = password_kek("pw2", &s1, &FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(a.as_bytes(), d.as_bytes());
    }

    #[test]
    fn secret_kek_info_separates() {
        let s = [7u8; 32];
        let a = secret_kek(&s, INFO_RECOVERY);
        let b = secret_kek(&s, INFO_TOKEN);
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes(), secret_kek(&s, INFO_RECOVERY).as_bytes());
    }
}
