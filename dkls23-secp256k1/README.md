# dkls23-secp256k1

[![Crates.io](https://img.shields.io/crates/v/dkls23-secp256k1.svg)](https://crates.io/crates/dkls23-secp256k1)
[![docs.rs](https://docs.rs/dkls23-secp256k1/badge.svg)](https://docs.rs/dkls23-secp256k1)

[DKLs23](https://eprint.iacr.org/2023/765.pdf) Threshold ECDSA for the **secp256k1** curve, with address derivation for multiple blockchains.

Built on [`dkls23-core`](https://crates.io/crates/dkls23-core) — provides concrete type aliases and chain-specific address computation.

## Supported Chains

| Chain | Function | Address Format |
|-------|----------|----------------|
| Ethereum (+ all EVM) | `compute_eth_address` | ERC-55 checksummed hex |
| Bitcoin | `compute_btc_address` | P2WPKH Bech32 (`bc1q...`) |
| Cosmos | `compute_cosmos_address` | Bech32 (configurable HRP) |
| TRON | `compute_tron_address` | Base58Check (`T...`) |

## Usage

```toml
[dependencies]
dkls23-secp256k1 = "0.5"
```

## Features

- `serde` (default) — serialization support for key shares and protocol messages
- `insecure-rng` — deterministic RNG for testing (never use in production)

## Protocol Overview

- **Distributed Key Generation (DKG)** — generate key shares without a trusted dealer
- **Threshold Signing** — produce ECDSA signatures with a subset of parties
- **Key Refresh** — rotate key shares without changing the public key
- **BIP-32 Derivation** — derive child keys from a master key share

For session orchestration, transport, and resumable flows, see [libtss](https://github.com/0xCarbon/libtss).

## License

Licensed under either of [Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
