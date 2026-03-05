use k256::AffinePoint;
use std::ops::Add;

fn test_add(a: AffinePoint, b: AffinePoint) -> AffinePoint {
    (a + b).to_affine()
}
fn main() {}