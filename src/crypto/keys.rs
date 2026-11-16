use super::{CryptoError, fill_random};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// A 256-bit secret key. Zeroized on drop; `Debug` never prints bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        fill_random(&mut b);
        Self(b)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key.as_bytes()).into())
}

/// Format: `[version u8 = 1][nonce 24][ciphertext + tag]`.
pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);
    let ct = cipher(key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption cannot fail");
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &Key32, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < 1 + NONCE_LEN + TAG_LEN || sealed[0] != VERSION {
        return Err(CryptoError::Format);
    }
    let nonce: [u8; NONCE_LEN] = sealed[1..1 + NONCE_LEN].try_into().unwrap();
    let pt = cipher(key)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &sealed[1 + NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

pub fn wrap_key(kek: &Key32, key: &Key32, aad: &[u8]) -> Vec<u8> {
    seal(kek, key.as_bytes(), aad)
}

pub fn unwrap_key(kek: &Key32, wrapped: &[u8], aad: &[u8]) -> Result<Key32, CryptoError> {
    let pt = open(kek, wrapped, aad)?;
    let bytes: [u8; 32] = pt.as_slice().try_into().map_err(|_| CryptoError::Format)?;
    Ok(Key32::from_bytes(bytes))
}

pub mod aad {
    pub fn umk_password(user_id: &str) -> String {
        format!("pm/v1/umk/password/{user_id}")
    }
    pub fn umk_recovery(user_id: &str) -> String {
        format!("pm/v1/umk/recovery/{user_id}")
    }
    pub fn umk_token(token_id: &str) -> String {
        format!("pm/v1/umk/token/{token_id}")
    }
    pub fn index_key(user_id: &str) -> String {
        format!("pm/v1/indexkey/{user_id}")
    }
    pub fn totp(user_id: &str) -> String {
        format!("pm/v1/totp/{user_id}")
    }
    pub fn dek(user_id: &str, doc_id: &str) -> String {
        format!("pm/v1/dek/{user_id}/{doc_id}")
    }
    pub fn blob(user_id: &str, doc_id: &str) -> String {
        format!("pm/v1/blob/{user_id}/{doc_id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip() {
        let kek = Key32::random();
        let k = Key32::random();
        let a = aad::umk_password("a");
        let w = wrap_key(&kek, &k, a.as_bytes());
        assert_eq!(w.len(), 1 + 24 + 32 + 16);
        let u = unwrap_key(&kek, &w, a.as_bytes()).unwrap();
        assert_eq!(u.as_bytes(), k.as_bytes());
    }

    #[test]
    fn unwrap_with_wrong_kek_fails() {
        let k = Key32::random();
        let w = wrap_key(&Key32::random(), &k, b"x");
        assert!(matches!(
            unwrap_key(&Key32::random(), &w, b"x"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn unwrap_with_other_aad_fails() {
        let kek = Key32::random();
        let k = Key32::random();
        let w = wrap_key(&kek, &k, aad::umk_password("a").as_bytes());
        for bad in [aad::umk_password("b"), aad::umk_recovery("a")] {
            assert!(matches!(
                unwrap_key(&kek, &w, bad.as_bytes()),
                Err(CryptoError::Decrypt)
            ));
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let kek = Key32::random();
        let mut w = wrap_key(&kek, &Key32::random(), b"x");
        *w.last_mut().unwrap() ^= 1;
        assert!(matches!(
            unwrap_key(&kek, &w, b"x"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn bad_version_byte_is_format_error() {
        let kek = Key32::random();
        let mut w = wrap_key(&kek, &Key32::random(), b"x");
        w[0] = 2;
        assert!(matches!(
            unwrap_key(&kek, &w, b"x"),
            Err(CryptoError::Format)
        ));
    }

    #[test]
    fn seal_uses_fresh_nonce() {
        let k = Key32::random();
        assert_ne!(seal(&k, b"hello", b"a"), seal(&k, b"hello", b"a"));
        let s = seal(&k, b"hello", b"a");
        assert_eq!(&**open(&k, &s, b"a").unwrap(), b"hello");
    }

    #[test]
    fn aad_strings_exact() {
        assert_eq!(aad::dek("u", "d"), "pm/v1/dek/u/d");
        assert_eq!(aad::blob("u", "d"), "pm/v1/blob/u/d");
        assert_eq!(aad::umk_token("t"), "pm/v1/umk/token/t");
        assert_eq!(aad::index_key("u"), "pm/v1/indexkey/u");
        assert_eq!(aad::totp("u"), "pm/v1/totp/u");
        assert_eq!(aad::umk_recovery("u"), "pm/v1/umk/recovery/u");
    }
}
