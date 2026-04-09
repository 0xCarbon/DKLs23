# dkls23

> **This crate is deprecated.** It has been replaced by a multi-crate workspace:
>
> - [`dkls23-secp256k1`](https://crates.io/crates/dkls23-secp256k1) — secp256k1 with Ethereum, Bitcoin, Cosmos, TRON address derivation
> - [`dkls23-secp256r1`](https://crates.io/crates/dkls23-secp256r1) — NIST P-256 with NEO3, Sui address derivation
> - [`dkls23-core`](https://crates.io/crates/dkls23-core) — curve-generic core (use directly only for custom curves)

## Migration

Replace in your `Cargo.toml`:

```diff
- dkls23 = "0.3"
+ dkls23-secp256k1 = "0.5"
```

The API is compatible — `dkls23-secp256k1` re-exports everything from `dkls23-core` plus chain-specific address functions.

## License

Licensed under either of [Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
