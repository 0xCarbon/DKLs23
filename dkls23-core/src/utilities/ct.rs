//! Constant-time selection on secret bits (OT choice and correlation bits).

use subtle::{Choice, ConditionallySelectable};

/// A secret bit as a [`Choice`], without a data-dependent branch.
pub(crate) fn choice(bit: bool) -> Choice {
    Choice::from(u8::from(bit))
}

/// `a` if `choice` is 0, `b` if it is 1, in constant time.
pub(crate) fn select_bytes<const N: usize>(a: &[u8; N], b: &[u8; N], choice: Choice) -> [u8; N] {
    core::array::from_fn(|i| u8::conditional_select(&a[i], &b[i], choice))
}

/// [`select_bytes`] for equal-length slices.
pub(crate) fn select_slice(a: &[u8], b: &[u8], choice: Choice) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "select_slice: unequal lengths");
    a.iter()
        .zip(b)
        .map(|(x, y)| u8::conditional_select(x, y, choice))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_without_mixing() {
        let a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        assert_eq!(select_bytes(&a, &b, choice(false)), a);
        assert_eq!(select_bytes(&a, &b, choice(true)), b);
        assert_eq!(select_slice(&a, &b, choice(false)), a.to_vec());
        assert_eq!(select_slice(&a, &b, choice(true)), b.to_vec());
    }
}
