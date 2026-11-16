use super::{CryptoError, fill_random};
use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// 32 random bytes shown to the user as 13 dash-separated groups of 4 base32 chars.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        fill_random(&mut b);
        Self(b)
    }

    /// Rebuilds a key from its 32 secret bytes (for example after unsealing it).
    pub fn from_secret(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_display(&self) -> String {
        let enc = BASE32_NOPAD.encode(&self.0);
        enc.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            s.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        if cleaned.len() != 52 {
            return Err(CryptoError::Format);
        }
        let mut dec = BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| CryptoError::Format)?;
        let res: Result<[u8; 32], _> = dec.as_slice().try_into();
        dec.zeroize();
        res.map(Self).map_err(|_| CryptoError::Format)
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_display_format() {
        let d = RecoveryKey::generate().to_display();
        assert_eq!(d.len(), 52 + 12);
        let groups: Vec<&str> = d.split('-').collect();
        assert_eq!(groups.len(), 13);
        for g in groups {
            assert_eq!(g.len(), 4);
            assert!(g.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')));
        }
    }

    #[test]
    fn recovery_parse_is_lenient() {
        let k = RecoveryKey::generate();
        let d = k.to_display().to_lowercase().replace('-', " - ");
        assert_eq!(RecoveryKey::parse(&d).unwrap().secret(), k.secret());
        let d2 = k.to_display().replace('-', "");
        assert_eq!(RecoveryKey::parse(&d2).unwrap().secret(), k.secret());
    }

    #[test]
    fn recovery_parse_rejects_bad_length() {
        assert!(matches!(
            RecoveryKey::parse("ABCD-EFGH"),
            Err(CryptoError::Format)
        ));
        assert!(RecoveryKey::parse("").is_err());
    }
}
