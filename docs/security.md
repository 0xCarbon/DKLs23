# Security Considerations

This document describes security properties, assumptions, and known limitations
of the DKLs23 implementation.

## Cryptographic Assumptions

The protocol's security relies on:
- **Hardness of ECDLP** on secp256k1
- **Random oracle model** (SHA-256 and SHA3-256 are used as instantiations)
- **Secure authenticated channels** between all parties

## OT Correlation Reuse

The DKLs23 protocol reuses base OT correlations (`OTESender` / `OTEReceiver`)
across multiple signing sessions for efficiency. This design is secure under
honest execution, but if a counterparty cheats during the COTe consistency check
or the multiplication verification step, information about the reused OT state
leaks.

**Mandatory response**: When a multiplication or consistency check fails, the
abort carries `AbortKind::BanCounterparty(index)`. The application MUST
permanently exclude the identified party from all future signing and refresh
sessions. Failure to do so enables gradual key extraction across sessions.

See Section 3.2 of the paper for the formal security argument.

## Fiat-Shamir Transcript Binding

Session IDs for the multiplication protocol and zero-share protocol include:
- Protocol domain separator
- Both party indices
- DKG session ID
- Signing session ID
- BIP-32 chain code (binds to the derived key path)

This prevents cross-session and cross-derivation transcript reuse.

## Scalar Tweaks

`protocols/tweak.rs` lets every party shift (`x + t`) or scale (`a·x`) its share
while the public key package moves by the same map. The reused OT and
multiplication state never depends on the share value, so a tweaked party is as
safe to sign with as a BIP-32 child. The chain code stays the same, so transcript
binding does not separate the base key from its tweaked keys; per-signature
freshness comes from `sign_id` as usual. A set of signers that disagrees on the
tweak fails the phase-3 public-key consistency check and aborts recoverably
(`PolynomialInconsistency`). A zero multiplicative factor and any tweak whose
result is the identity point are rejected. The additive tweak may itself be
secret (LND's revocation tweak mixes in a per-commitment secret): callers should
hold it in a zeroizing container; the crate never logs or formats scalars.

## Memory Safety

- `#![forbid(unsafe_code)]` is enforced crate-wide.
- All types holding secret material implement `Zeroize` and `ZeroizeOnDrop`:
  - `OTESender`, `OTEReceiver` (OT correlations)
  - `MulSender`, `MulReceiver`, `MulDataToKeepReceiver` (multiplication state)
  - `ZeroShare`, `SeedPair` (shared seeds)
  - `DerivData` (derived key share and chain code)
  - `KeepPhase1to2`, `KeepPhase2to3` (signing intermediates)
  - `UniqueKeep1to2`, `UniqueKeep2to3` (signing intermediates)
  - `Party` (manual `Zeroize` + `Drop` implementation)

## Side-Channel Resistance

- Scalar arithmetic is delegated to `k256`, which uses constant-time operations
  from the `subtle` crate.
- Hash comparisons in the commitment scheme (`commits.rs`) use standard `==` on
  `[u8; 32]`. This is a potential timing side-channel, though exploitation
  requires an attacker who can both supply malicious messages AND measure
  sub-microsecond timing differences.

## Deterministic RNG (`insecure-rng` feature)

The `insecure-rng` feature is scoped to `cfg(test)` only. Even if the feature
flag is enabled in a production build, the secure `ThreadRng` is always returned.
This makes it impossible to accidentally ship deterministic randomness.

## Known Limitations

1. **No hardened BIP-32 derivation**: Only non-hardened derivation is supported
   because no party holds the full secret key.
2. **No proactive security refresh schedule**: The refresh protocol exists but
   the crate does not enforce periodic refresh. Applications should implement
   their own refresh schedule.
3. **u8 party indices**: Party counts are limited to 255 by the `u8` type.
