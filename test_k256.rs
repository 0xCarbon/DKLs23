use k256::{Scalar, elliptic_curve::bigint::{U256, Encoding}};
fn main() {
    let x = U256::ZERO;
    let b: [u8; 32] = x.to_be_bytes();
}
