//! The umbrella crate exposes the core at the root and each enabled curve as a module.

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_reexports() {
    let _: Option<dkls23::secp256k1::Party> = None;
    let _: Option<dkls23::protocols::Party<k256::Secp256k1>> = None::<dkls23::secp256k1::Party>;
    let pk = k256::AffinePoint::GENERATOR;
    assert_eq!(
        dkls23::secp256k1::compute_eth_address(&pk),
        dkls23_secp256k1::compute_eth_address(&pk)
    );
}

#[cfg(feature = "secp256r1")]
#[test]
fn secp256r1_reexports() {
    let _: Option<dkls23::protocols::Party<p256::NistP256>> = None::<dkls23::secp256r1::Party>;
    let pk = p256::AffinePoint::GENERATOR;
    assert_eq!(
        dkls23::secp256r1::compute_neo3_address(&pk),
        dkls23_secp256r1::compute_neo3_address(&pk)
    );
}
