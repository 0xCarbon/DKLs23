#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl EcdsaSignature {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    #[must_use]
    pub fn to_bytes_with_recovery(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.recovery_id;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_signature_to_bytes() {
        let sig = EcdsaSignature {
            r: [0xAA; 32],
            s: [0xBB; 32],
            recovery_id: 1,
        };

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[..32], &[0xAA; 32]);
        assert_eq!(&bytes[32..], &[0xBB; 32]);

        let bytes_with_rec = sig.to_bytes_with_recovery();
        assert_eq!(bytes_with_rec.len(), 65);
        assert_eq!(&bytes_with_rec[..32], &[0xAA; 32]);
        assert_eq!(&bytes_with_rec[32..64], &[0xBB; 32]);
        assert_eq!(bytes_with_rec[64], 1);
    }
}
