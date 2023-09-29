//! A library for dealing with the `DKLs23` protocol (see <https://eprint.iacr.org/2023/765.pdf>)
//! and related protocols.
//! 
//! Written and used by Alore.

pub mod protocols;
pub mod utilities;

// The following constants should not be changed!
// They are taken from the implementation of DKLs19:
// https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs

/// Computational security parameter `lambda_c` from `DKLs23`.
/// We take it to be the same as the parameter `kappa`.
pub const RAW_SECURITY: u16 = 256;
/// `RAW_SECURITY` divided by 8 (used for arrays of bytes)
pub const SECURITY: u16 = 32;

/// Statistical security parameter `lambda_s` from `DKLs23`.
pub const STAT_SECURITY: u16 = 80;
