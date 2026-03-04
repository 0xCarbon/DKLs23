# Domain Separation v1 Migration

This document records the PR5 migration from ad-hoc `hash(msg, salt)` usage to
explicit domain-separated tagged hashes.

## Design

- Canonical encoding: `len(tag) || tag || len(component_0) || component_0 || ...`
- Hash primitive: SHA-256
- API:
  - `tagged_hash(tag, components)`
  - `tagged_hash_as_int(tag, components)`
  - `tagged_hash_as_scalar(tag, components)`
- Tag registry: [`src/utilities/oracle_tags.rs`](../src/utilities/oracle_tags.rs)
- Safety check: `ALL_TAGS` uniqueness test (`test_oracle_tags_are_unique`)

## SHA-256 Decision

This migration keeps SHA-256 and strengthens domain separation through explicit
tags and length-delimited transcript encoding. This is the conservative option:
minimal protocol churn while removing tag-collision ambiguity. A future move to
SHAKE/cSHAKE remains optional and independent.

## Call-Site Migration Table

| File | Prior pattern | New tag(s) |
|---|---|---|
| `src/utilities/commits.rs` | `hash(msg, salt)` | `TAG_COMMITMENT` |
| `src/utilities/proofs.rs` | ad-hoc proof salts / tagged `session_id` suffixes | `TAG_DLOG_PROOF_FISCHLIN`, `TAG_DLOG_PROOF_COMMITMENT`, `TAG_ENCPROOF_FS` |
| `src/utilities/zero_shares.rs` | `hash_as_scalar(seed, session_id)` | `TAG_ZERO_SHARE_FRAGMENT` |
| `src/utilities/ot/base.rs` | `"Receiver"/"Sender"` prefixes and `"DLogProof"/"EncProof"` SID suffixes | `TAG_OT_BASE_H`, `TAG_OT_BASE_MSG` |
| `src/utilities/ot/extension.rs` | salt concatenation for PRG/chi/randomization | `TAG_OTE_PRG`, `TAG_OTE_CHI`, `TAG_OTE_RANDOMIZE` |
| `src/utilities/multiplication.rs` | salt concatenation for gadget/chi/verify | `TAG_MUL_GADGET`, `TAG_MUL_CHI_TILDE`, `TAG_MUL_CHI_HAT`, `TAG_MUL_VERIFY` |
| `src/protocols/refresh.rs` | ad-hoc fast-refresh OT rerandomization salts | `TAG_REFRESH_FAST_R0`, `TAG_REFRESH_FAST_R1`, `TAG_REFRESH_FAST_B` |

## Compatibility and Release Impact

This migration is protocol-breaking and released as `0.2.0`:

- Mixed `0.1.x`/`0.2.x` participants are incompatible.
- In-flight signing/refresh sessions across the version boundary are invalid.
- Persisted party state should be regenerated (`re_key`) or refreshed entirely
  with homogeneous `0.2.x` peers before continued operation.
