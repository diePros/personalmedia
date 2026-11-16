pub mod kdf;
pub mod keys;
pub mod recovery;
pub mod stream;

pub use kdf::{Argon2Params, INFO_RECOVERY, INFO_TOKEN, password_kek, secret_kek};
pub use keys::{Key32, aad, open, seal, unwrap_key, wrap_key};
pub use recovery::RecoveryKey;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid format")]
    Format,
    #[error("key derivation failed")]
    Kdf,
}

/// Fill `buf` from the OS CSPRNG.
pub(crate) fn fill_random(buf: &mut [u8]) {
    use rand::TryRng;
    rand::rngs::SysRng
        .try_fill_bytes(buf)
        .expect("OS CSPRNG unavailable");
}
