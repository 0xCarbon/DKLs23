# dkls23

[![Crates.io](https://img.shields.io/crates/v/dkls23.svg)](https://crates.io/crates/dkls23)
[![docs.rs](https://docs.rs/dkls23/badge.svg)](https://docs.rs/dkls23)

[DKLs23](https://eprint.iacr.org/2023/765.pdf) Threshold ECDSA — one dependency for the core protocol and its curve instantiations.

The curve-generic core ([`dkls23-core`](https://crates.io/crates/dkls23-core)) is re-exported at the crate root, and each curve is a module:

| Feature | Module | Curve | Chains |
|---------|--------|-------|--------|
| `secp256k1` (default) | `dkls23::secp256k1` | secp256k1 | Ethereum (+ all EVM), Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Cosmos, TRON, XRP, Filecoin, Tezos |
| `secp256r1` | `dkls23::secp256r1` | NIST P-256 | NEO3, Sui, Tezos |

## Usage

```toml
[dependencies]
dkls23 = "0.6"                                          # secp256k1
dkls23 = { version = "0.6", features = ["secp256r1"] }  # both curves
```

You can also depend on [`dkls23-secp256k1`](https://crates.io/crates/dkls23-secp256k1) or [`dkls23-secp256r1`](https://crates.io/crates/dkls23-secp256r1) directly; this crate only re-exports them.

## Features

- `secp256k1` (default) — secp256k1 instantiation
- `secp256r1` — NIST P-256 instantiation
- `serde` (default) — serialization support for key shares and protocol messages
- `insecure-rng` — deterministic RNG for testing (never use in production)

## Upgrading from 0.3

`dkls23` 0.3 re-exported `dkls23-secp256k1` at the crate root. In 0.6 the secp256k1 items are under `dkls23::secp256k1` (for example `dkls23::secp256k1::Party` and `dkls23::secp256k1::compute_eth_address`); the generic protocol API stays at the root.

For session orchestration, transport, and resumable flows, see [libtss](https://github.com/0xCarbon/libtss).

## License

Licensed under either of [Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
