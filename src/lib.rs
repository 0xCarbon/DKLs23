pub mod protocols;
pub mod utilities;

// The following constants should not be changed!
// They are taken from the implementation of DKLs19.

/// Computational security parameter `lambda_c` from `DKLs23`.
/// We take it to be the same as the parameter `kappa`.
pub const RAW_SECURITY: u16 = 256;
/// `RAW_SECURITY` divided by 8 (used for arrays of bytes)
pub const SECURITY: u16 = 32;

/// Statistical security parameter `lambda_s` from `DKLs23`.
pub const STAT_SECURITY: u16 = 80;
