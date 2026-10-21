# Security Considerations

This document describes security properties, assumptions, and known limitations
of the DKLs23 implementation.

## Cryptographic Assumptions

The protocol's security relies on:
- **Hardness of ECDLP** on the curve in use (secp256k1 or P-256)
- **Random oracle model**, instantiated with SHA-256 (including RFC 9380
  `hash_to_curve` with `expand_message_xmd` for the base OT point); Keccak-256
  and BLAKE2b appear only in address helpers
- **Authenticated and confidential (encrypted) channels** between all parties:
  DKG and refresh send secret material peer-to-peer in the clear

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

Session IDs for the multiplication protocol and zero-share protocol are
tagged, length-delimited hashes of:
- DKG session ID
- Signing session ID (`SignData::sign_id`)
- BIP-32 chain code and public key (bind to the key in use, including
  BIP-32 children and BOLT 3 derived keys)
- Message hash and signer set
- Both party indices, in multiplication-role order (multiplication only)

The multiplication's OT extension does not rely on this session ID being
unique. Each execution also mixes in fresh randomness from both parties,
carried in messages the protocol already sends:
- the receiver's nonce (in its Step 3 message) enters the PRG expansion and
  the consistency challenges, so its pads are fresh in every execution;
- the sender's salt (sent with `tau`) enters the output randomization, so its
  outputs are fresh in every execution.

Each side's freshness protects that side even if the other repeats its value,
so reusing a `sign_id` (for example on a retry after an abort) does not leak
key material. The phase-2 session binding also covers both parties' phase-1
OT extension nonces, so a message mixing attempts (built on a stale phase-1
message, or answering a different attempt than the one whose commitment we
hold) is a recoverable `SessionBindingMismatch`, not a ban. A fresh
`sign_id` per attempt is still recommended.

## Memory Safety

- `#![forbid(unsafe_code)]` is enforced crate-wide.
- All types holding secret material implement `Zeroize` and `ZeroizeOnDrop`:
  - `OTESender`, `OTEReceiver` (OT correlations)
  - `MulSender`, `MulReceiver`, `MulDataToKeepReceiver` (multiplication state)
  - `ZeroShare`, `SeedPair` (shared seeds)
  - `DerivData` (derived key share and chain code)
  - `KeepPhase1to2`, `KeepPhase2to3` (signing intermediates)
  - `UniqueKeep1to2`, `UniqueKeep2to3` (signing intermediates)
  - `SignData`, `TransmitPhase1to2`, `TransmitPhase2to3`, `Broadcast3to4`,
    `MulDataToReceiver` (signing data and messages)
  - `Party` (manual `Zeroize` + `Drop` implementation)

## Side-Channel Resistance

- Scalar and point arithmetic is delegated to `k256` / `p256`, which use
  constant-time operations from the `subtle` crate.
- Commitment checks (`commits.rs`) compare digests in constant time
  (`subtle::ConstantTimeEq`).
- Known limitation: the OT extension (`field_mul` on the receiver's choice
  bits, output selection by choice bit), the multiplication (accumulation by
  choice bit) and the fast refresh (selection by correlation bit) branch on
  secret bits. An attacker with fine-grained local timing or microarchitectural
  observation of a party could learn some of those bits; remote timing is not
  expected to resolve them. Constant-time selection is planned.

## BOLT 3 Key Derivation

`protocols/bolt3.rs` derives Lightning per-commitment and revocation key
shares. The tweaks are BOLT 3 hashes of public points that every party
computes itself; there is no API that applies a caller-supplied scalar. This is
deliberate: a signature `(r, s)` on hash `m` under `a*X` gives the valid
signature `(r, s/a)` on hash `m/a` under `X`, so whoever chooses a
multiplicative factor `a` could
turn an approved signature into one under the base key on a message of their
choice.

With the factor and offset derived by hashing, a caller can grind the
per-commitment point but cannot pick the outputs. A signature under a derived
key `a*X + c*G` gives the signature `(r, s/a)` under `X` on the hash
`(m + r*c)/a`, which depends
on the nonce `r`; `r` is fixed only after the message and the per-commitment
point. This relies on two things: parties sign hashes they compute from
transactions they validate, and there are no presignatures (no `r` known
before the message and key are fixed).

Derived parties share the base key's OT and multiplication state. Signing
session ids include the public key, so the base key and every derived key
run their multiplications under distinct ids for the same `sign_id`. Because
the state is shared:
- a `BanCounterparty` abort under any derived key applies to the base key
  and every key derived from it;
- a leaked derived private key reveals the base key (`x = (x' - c)/a`, with
  `a` public; `c` is public for `bolt3_derive` and known to the counterparty
  for the revocation key), and a leaked derived share reveals the base share
  the same way.

Signers that derive with different per-commitment points hold different
public keys and abort with a recoverable `SessionBindingMismatch`. The
revocation derivation takes the counterparty's per-commitment secret and
rejects it unless it matches the per-commitment point; callers should hold it
in zeroizing storage.

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
