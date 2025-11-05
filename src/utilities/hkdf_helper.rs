use hkdf::Hkdf;
use k256::elliptic_curve::bigint::{Encoding, U512};
use k256::elliptic_curve::ops::Reduce;
use k256::Scalar;
use sha2::Sha256;

/// HKDF expand with automatic chunking (never exceeds 8160 bytes per call).
pub fn hkdf_expand(zk_seed: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, zk_seed);
    let max_bytes = 255 * 32; // RFC 5869 (SHA-256)
    let mut out = Vec::with_capacity(out_len);

    let mut offset = 0usize;
    let mut ctr: u32 = 0;

    while offset < out_len {
        ctr += 1;
        let take = core::cmp::min(max_bytes, out_len - offset);

        // domain-separate each chunk: info || ctr_be
        let mut info_ctr = Vec::with_capacity(info.len() + 4);
        info_ctr.extend_from_slice(info);
        info_ctr.extend_from_slice(&ctr.to_be_bytes());

        let mut block = vec![0u8; take];
        hk.expand(&info_ctr, &mut block).expect("HKDF expand");
        out.extend_from_slice(&block);
        offset += take;
    }
    out
}

/// Expand `count` × 32-byte blocks (for seeds0/seeds1/…)
pub fn expand_hashoutputs(zk_seed: &[u8; 32], info: &[u8], count: usize) -> Vec<[u8; 32]> {
    let bytes = hkdf_expand(zk_seed, info, 32 * count);
    bytes
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect()
}

/// Expand `count` × SECURITY-byte blocks (for HashOutput arrays)
pub fn expand_hashoutputs_truncated(zk_seed: &[u8; 32], info: &[u8], count: usize, size: usize) -> Vec<Vec<u8>> {
    let bytes = hkdf_expand(zk_seed, info, 32 * count);
    bytes
        .chunks_exact(32)
        .map(|c| c[..size].to_vec())
        .collect()
}

/// Expand to `count` booleans (for correlation bits)
pub fn expand_bools(zk_seed: &[u8; 32], info: &[u8], count: usize) -> Vec<bool> {
    let byte_len = (count + 7) / 8;
    let bytes = hkdf_expand(zk_seed, info, byte_len);
    let mut out = Vec::with_capacity(count);
    for (i, b) in bytes.iter().enumerate() {
        for bit in 0..8 {
            if i * 8 + bit >= count {
                break;
            }
            out.push(((b >> bit) & 1) == 1);
        }
    }
    out
}

/// Expand to `count` Scalars with guaranteed validity (reduce mod n; no rejection)
pub fn expand_scalars(zk_seed: &[u8; 32], info: &[u8], count: usize) -> Vec<Scalar> {
    let bytes = hkdf_expand(zk_seed, info, 32 * count);
    bytes
        .chunks_exact(32)
        .map(|c| {
            let mut wide = [0u8; 64];
            wide[32..].copy_from_slice(c); // put 32 bytes in low half
            let num = U512::from_be_bytes(wide); // needs `Encoding` in scope
            Scalar::reduce(num) // needs `Reduce` in scope
        })
        .collect()
}
