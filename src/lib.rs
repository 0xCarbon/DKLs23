pub mod protocols;
pub mod utilities;

//Computational security parameter lambda_c from DKLs23 (divided by 8)
const SECURITY: usize = 32; //32*8 = 256 bits