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

### OT Extension (`utilities/ot/extension.rs`)

Implements Functionality 3 from DKLs19 using:
- **KOS** corrected protocol (Fig. 10 in <https://eprint.iacr.org/2015/546.pdf>)
- **SoftSpokenOT** subfield VOLE for efficiency
- **DKLs18** transfer step (Protocol 9 from <https://eprint.iacr.org/2018/499.pdf>)
- **Fiat-Shamir** heuristic for non-interactive consistency check (reduces rounds)

The "forced-reuse" technique from DKLs23 is implemented: a single batch of Bob's
OT instances is reused across all elements of Alice's input vector.

**Security note**: OT correlations are reused across signing sessions. If the
COTe consistency check fails, the counterparty MUST be permanently banned from
all future sessions (see `AbortKind::BanCounterparty`).

### Multiplication (`utilities/multiplication.rs`)

Realizes Functionality 3.5 (Random Vector OLE) using Protocol 1 from DKLs19.
Produces correlated randomness `(a, b)` such that `a * x + b = c` where `x` is
the receiver's input. Used to compute shares of products during signing.

### Zero Shares (`utilities/zero_shares.rs`)

Functionality 3.4: produces shares of zero using committed seeds. Each pair of
parties shares a seed; the share of zero is computed as a sum of PRF evaluations
over the session ID, with signs determined by party ordering.

### Proofs (`utilities/proofs.rs`)

- **Schnorr DLog proof** with randomized Fischlin transform (R=64, L=4, T=32)
  for non-interactive proofs in the random oracle model.
- **Chaum-Pedersen proof** for equality of discrete logarithms.
- **Encryption proof** (EncProof) for the DKLs18 OT transfer step.

## Protocol Flows

### DKG (4 phases + 5 steps)

1. **Phase 1**: Sample polynomial, commit to evaluation.
2. **Phase 2**: Exchange polynomial evaluations and commitments.
3. **Phase 3**: Decommit, verify proofs, reconstruct public key via Lagrange
   interpolation in the exponent.
4. **Phase 4**: Initialize OT correlations, zero-share seeds, multiplication
   setup, and BIP-32 chain code via XOR of committed auxiliary values.

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

### Key Derivation (`protocols/derivation.rs`)

BIP-32 non-hardened derivation adapted for threshold setting. Each party derives
their share individually so the reconstructed key corresponds to BIP-32
derivation of the original master key.

## Security Boundaries

### Abort Classification

Aborts are classified via `AbortKind`:
- `Recoverable`: Protocol failure, safe to retry.
- `BanCounterparty(index)`: The counterparty leaked information about reusable
  OT state. They MUST be permanently excluded from future sessions.

### Trust Model

- Messages are authenticated but not encrypted (the protocol provides its own
  confidentiality via OT).
- The orchestrator is trusted to route messages correctly.
- Party indices must be in `[1, share_count]` and are validated at signing entry.

### Zeroization

Secret material (key shares, OT correlations, multiplication state) is
automatically zeroed on drop via the `zeroize` crate.
