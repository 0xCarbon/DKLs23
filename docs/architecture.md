# DKLs23 Architecture

This document describes the internal architecture of the DKLs23 threshold ECDSA
library. For API usage, see the rustdoc (`cargo doc --open`).

## Protocol Stack

The implementation follows the paper's layered design:

```
 Signing (Protocol 3.6)          DKG (Protocol 9.1 from DKLs19)
        |                                |
        v                                v
 Multiplication (Functionality 3.5)   Proofs (Schnorr, Chaum-Pedersen)
        |
        v
 OT Extension (KOS + SoftSpokenOT)
        |
        v
 Base OT (Zhou et al. endemic OT)
```

### Base OT (`utilities/ot/base.rs`)

Implements the endemic OT protocol from Zhou et al. The receiver samples a
random scalar `r` using `Scalar::random()` (not vulnerable to the Fordefi
"Devious Transfer" attack, which affects implementations that use
`Scalar::from_bytes` on untrusted input).

The point `h` is derived from the session id and the receiver's seed with
RFC 9380 `hash_to_curve`, using the curve's random-oracle suite from its
`GroupDigest` implementation (`secp256k1_XMD:SHA-256_SSWU_RO_` for secp256k1,
`P256_XMD:SHA-256_SSWU_RO_` for P-256), matching the hash `{0,1}* -> G` in
the paper. `DklsCurve` therefore requires `GroupDigest`; for `k256` and `p256`
enable their `group-digest` feature.

### OT Extension (`utilities/ot/extension.rs`)

Implements Functionality 3 from DKLs19 using:
- **KOS** corrected protocol (Fig. 10 in <https://eprint.iacr.org/2015/546.pdf>)
- **SoftSpokenOT** subfield VOLE for efficiency
- **DKLs18** transfer step (Protocol 9 from <https://eprint.iacr.org/2018/499.pdf>)
- **Fiat-Shamir** heuristic for non-interactive consistency check (reduces rounds)

The "forced-reuse" technique from DKLs23 is implemented: a single batch of Bob's
OT instances is reused across all elements of Alice's input vector.

Each execution runs under a session id that includes a fresh receiver nonce
(sent with `u`), and the sender's output randomization includes a fresh salt
(sent with `tau`), so a repeated caller session id never repeats the receiver's
pads or the sender's outputs.

**Security note**: OT correlations are reused across signing sessions. If the
COTe consistency check fails, the counterparty MUST be permanently banned from
all future sessions (see `AbortKind::BanCounterparty`).

### Multiplication (`utilities/multiplication.rs`)

Realizes Functionality 3.5 (Random Vector OLE) using Protocol 1 from DKLs19.
Produces correlated randomness `(a, b)` such that `a * x + b = c` where `x` is
the receiver's input. Used to compute shares of products during signing.

The shared random values `chi_tilde`, `chi_hat` of the consistency check are
derived by Fiat-Shamir from the whole OT extension transcript, including the
receiver's nonce, the sender's salt and corrections `tau` (DKLs19, Protocol 9).

### Zero Shares (`utilities/zero_shares.rs`)

Functionality 3.4: produces shares of zero using committed seeds. Each pair of
parties shares a seed; the share of zero is computed as a sum of PRF evaluations
over the session ID, with signs determined by party ordering.

### Proofs (`utilities/proofs.rs`)

- **Schnorr DLog proof** with randomized Fischlin transform (R=64, L=4, T=32)
  for non-interactive proofs in the random oracle model.
- **Chaum-Pedersen proof** for equality of discrete logarithms.
- **Encryption proof** (EncProof) for the receiver of the base OT (endemic OT of
  Zhou et al.), proving its message encrypts a bit.

## Protocol Flows

### DKG (4 phases + 5 steps)

1. **Phase 1** (Steps 1-2): Sample a polynomial and evaluate it for every party
   (sent peer-to-peer, confidentially).
2. **Phase 2** (Step 3): Sum the received evaluations into the key share,
   commit to its proof of knowledge; send zero-share seed and chain-code
   commitments.
3. **Phase 3**: Initialization only: reveal zero-share seeds and chain-code
   contributions, and run the base OT that sets up each pair's multiplication.
4. **Phase 4** (Step 5): Verify the proofs and reconstruct the public key via
   Lagrange interpolation in the exponent; verify the seed and chain-code
   commitments and finish the multiplication setup.

Output: `Party` struct ready for signing.

### Signing (4 phases)

1. **Phase 1** (Step 4-6): Sample instance key and inversion mask. Start
   multiplication protocol (receiver side). Commit to instance point.
2. **Phase 2** (Step 7): Compute Lagrange coefficient and key share. Run
   multiplication protocol (sender side). Transmit gamma values and instance
   point.
3. **Phase 3** (Steps 8-9): Verify commitments. Finish multiplication (receiver
   side). Aggregate instance point and verify consistency of u/v variables.
   Broadcast partial signature shares.
4. **Phase 4** (Step 10): Aggregate signature shares, compute final ECDSA
   signature, and verify.

### Refresh

Two variants: full refresh (re-runs DKG-like setup) and faster refresh (updates
OT correlations using shared seeds without re-running base OT).

After a refresh a party's session id is `H(previous session id, refresh id)`,
so parties that adopted different refreshes never share a session id, and
`PublicKeyPackage::refresh` updates a public key package's verifying shares
from the refresh's proof commitments. Zero-share seed commitments are bound
to the session and direction.

### Share Repair (`protocols/repair.rs`)

A lost root share is rebuilt under the same group key. At least `threshold`
helpers each send the target `poly_point · λ(target) + mask`, where the masks
are zero-sum shares from their pairwise zero-share seeds
(`ZeroShare::try_compute`), bound to the session, public key, repair id,
target and helper set. `repair_assemble` checks the sum against the target's
verifying share and returns a hollow party (no OT or zero-share state). A
complete refresh across all `n` parties makes it a signing share; refreshed
shares do not sign with older ones, but every party must also erase its old
share (and backups), since a refresh cannot revoke shares someone keeps.
Authorizing the target is the application's job.

### Key Derivation (`protocols/derivation.rs`)

BIP-32 non-hardened derivation adapted for threshold setting. Each party derives
their share individually so the reconstructed key corresponds to BIP-32
derivation of the original master key.

### BOLT 3 Key Derivation (`protocols/bolt3.rs`)

Lightning's per-commitment keys ([BOLT 3](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation)):
`Party::bolt3_derive` and `Party::bolt3_derive_revocation` map each party's
share, and the `PublicKeyPackage` functions of the same name map the group key
and every verifying share, by the same affine map `x -> a*x + c`. Because the
Lagrange coefficients used in signing sum to one, the reconstructed key moves
by exactly that map. Each party computes the BOLT 3 hashes itself from the
group key and the per-commitment point; the revocation derivation also takes
the per-commitment secret and checks it against the point. As in BIP-32
derivation, OT correlations, zero-share seeds and multiplication state are
reused; signing session ids include the public key to keep each key's
sessions distinct. Unlike BIP-32, the chain code is left unchanged.

## Security Boundaries

### Abort Classification

Aborts are classified via `AbortKind`:
- `Recoverable`: Protocol failure, safe to retry.
- `BanCounterparty(index)`: The counterparty leaked information about reusable
  OT state. They MUST be permanently excluded from future sessions.

Signing messages carry a session binding (DKG session id, sign id, key, message
hash, signer set, phase, direction and the pair's multiplication setup (both
public gadgets); phase-2 messages also cover both parties' phase-1 OT
extension nonces, which are fresh per attempt). It is
checked before any OT or multiplication work, so a message from a different
session or attempt yields a `Recoverable` `SessionBindingMismatch` rather than
a ban.

### Trust Model

- Every message must be authenticated, and peer-to-peer messages must also be
  confidential. DKG and refresh send secret material peer-to-peer in the
  clear (polynomial evaluations, zero-share seeds): an eavesdropper on those
  messages learns key shares. Use authenticated, encrypted channels (e.g. TLS
  or a Noise session per pair).
- The orchestrator is trusted to route messages correctly.
- Party indices must be in `[1, share_count]` and are validated at signing entry.

### Zeroization

Secret material (key shares, OT correlations, multiplication state) is
automatically zeroed on drop via the `zeroize` crate.
