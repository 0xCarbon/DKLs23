pub mod protocols;
pub mod utilities;

//The following constants should not be changed!
//They are taken from the implementation of DKLs19.

//Computational security parameter lambda_c from DKLs23.
//We take it to be the same as the parameter kappa.
const RAW_SECURITY: usize = 256;
const SECURITY: usize = 32; //Used for arrays of bytes (32*8 = 256 bits).

//Statistical security parameter lambda_s from DKLs23.
const STAT_SECURITY: usize = 80;
