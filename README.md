<div align="center">
    <picture>
        <source srcset=".assets/dkls23-banner.png"  media="(prefers-color-scheme: dark)">
        <img src=".assets/dkls23-banner.png" alt="DKLs logo">
    </picture>

  <p>
    <a href="https://github.com/0xCarbon/DKLs23/actions?query=workflow%3Abackend-ci">
      <img src="https://github.com/0xCarbon/DKLs23/actions/workflows/backend-ci.yml/badge.svg?event=push" alt="Test Status">
    </a>
  </p>
</div>

## Overview

DKLs23 is an open-source implementation of the [DKLs23 Threshold ECDSA protocol](https://eprint.iacr.org/2023/765.pdf). It computes ECDSA signatures across multiple parties, each holding a key share, without ever reconstructing the secret key in a single location.

## Crates

| Crate | Description | |
|-------|-------------|---|
| [`dkls23-core`](dkls23-core/) | Curve-generic core protocol | [![crates.io](https://img.shields.io/crates/v/dkls23-core.svg)](https://crates.io/crates/dkls23-core) |
| [`dkls23-secp256k1`](dkls23-secp256k1/) | secp256k1 — Ethereum, Bitcoin, Cosmos, TRON | [![crates.io](https://img.shields.io/crates/v/dkls23-secp256k1.svg)](https://crates.io/crates/dkls23-secp256k1) |
| [`dkls23-secp256r1`](dkls23-secp256r1/) | NIST P-256 — NEO3, Sui | [![crates.io](https://img.shields.io/crates/v/dkls23-secp256r1.svg)](https://crates.io/crates/dkls23-secp256r1) |

## libtss

For session orchestration, transport, and resumable protocol flows, see [libtss](https://github.com/0xCarbon/libtss) — a higher-level library built on top of DKLs23 that handles multi-party communication and state management.

## Getting Started

1. **Install Rust**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Add a dependency** (pick your curve)
```bash
cargo add dkls23-secp256k1   # or dkls23-secp256r1
```

3. **Clone for development**
```bash
git clone https://github.com/0xCarbon/DKLs23
cd DKLs23
cargo test
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

## Security

For information on how to report security vulnerabilities, please see our [SECURITY.md](SECURITY.md).

## Code of Conduct

This project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to abide by its terms.

## License

Licensed under either of
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

## Authors

See the list of [contributors](https://github.com/0xCarbon/DKLs23/contributors) who participated in this project.
