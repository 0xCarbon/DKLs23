//! Domain-separation tags for protocol oracles.
//!
//! Every internal protocol oracle must use a dedicated tag from this module.
//! Tags are versioned (`.../v1`) to allow explicit, auditable migrations.

/// Commitment hash oracle.
pub const TAG_COMMITMENT: &[u8] = b"dkls23/commitment/v1";

/// DLog randomized Fischlin transcript oracle.
pub const TAG_DLOG_PROOF_FISCHLIN: &[u8] = b"dkls23/proofs/dlog/fischlin/v1";
/// DLog proof commitment oracle.
pub const TAG_DLOG_PROOF_COMMITMENT: &[u8] = b"dkls23/proofs/dlog/commitment/v1";
/// EncProof Fiat-Shamir oracle.
pub const TAG_ENCPROOF_FS: &[u8] = b"dkls23/proofs/enc/fs/v1";

/// Zero-share fragment derivation oracle.
pub const TAG_ZERO_SHARE_FRAGMENT: &[u8] = b"dkls23/zero-share/fragment/v1";

/// Base OT hash-to-point oracle.
pub const TAG_OT_BASE_H: &[u8] = b"dkls23/ot/base/h/v1";
/// Base OT message derivation oracle.
pub const TAG_OT_BASE_MSG: &[u8] = b"dkls23/ot/base/msg/v1";

/// OTE PRG expansion oracle.
pub const TAG_OTE_PRG: &[u8] = b"dkls23/ot/extension/prg/v1";
/// OTE consistency-check chi oracle.
pub const TAG_OTE_CHI: &[u8] = b"dkls23/ot/extension/chi/v1";
/// OTE final randomization oracle.
pub const TAG_OTE_RANDOMIZE: &[u8] = b"dkls23/ot/extension/randomize/v1";

/// Multiplication public gadget oracle.
pub const TAG_MUL_GADGET: &[u8] = b"dkls23/mul/gadget/v1";
/// Multiplication chi-tilde oracle.
pub const TAG_MUL_CHI_TILDE: &[u8] = b"dkls23/mul/chi-tilde/v1";
/// Multiplication chi-hat oracle.
pub const TAG_MUL_CHI_HAT: &[u8] = b"dkls23/mul/chi-hat/v1";
/// Multiplication verify-r oracle.
pub const TAG_MUL_VERIFY: &[u8] = b"dkls23/mul/verify/v1";

/// Fast-refresh OT re-randomization oracle for `r0'`.
pub const TAG_REFRESH_FAST_R0: &[u8] = b"dkls23/refresh/fast/r0/v1";
/// Fast-refresh OT re-randomization oracle for `r1'`.
pub const TAG_REFRESH_FAST_R1: &[u8] = b"dkls23/refresh/fast/r1/v1";
/// Fast-refresh OT re-randomization oracle for `b'`.
pub const TAG_REFRESH_FAST_B: &[u8] = b"dkls23/refresh/fast/b/v1";

/// Registry of all internal tags.
pub const ALL_TAGS: &[&[u8]] = &[
    TAG_COMMITMENT,
    TAG_DLOG_PROOF_FISCHLIN,
    TAG_DLOG_PROOF_COMMITMENT,
    TAG_ENCPROOF_FS,
    TAG_ZERO_SHARE_FRAGMENT,
    TAG_OT_BASE_H,
    TAG_OT_BASE_MSG,
    TAG_OTE_PRG,
    TAG_OTE_CHI,
    TAG_OTE_RANDOMIZE,
    TAG_MUL_GADGET,
    TAG_MUL_CHI_TILDE,
    TAG_MUL_CHI_HAT,
    TAG_MUL_VERIFY,
    TAG_REFRESH_FAST_R0,
    TAG_REFRESH_FAST_R1,
    TAG_REFRESH_FAST_B,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_oracle_tags_are_unique() {
        let mut set = HashSet::new();
        for tag in ALL_TAGS {
            assert!(set.insert(*tag), "duplicate tag: {:?}", tag);
        }
    }
}
