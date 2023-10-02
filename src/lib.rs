use wasm_bindgen::prelude::*;

pub mod protocols;
pub mod utilities;

//The following constants should not be changed!
//They are taken from the implementation of DKLs19.

//Computational security parameter lambda_c from DKLs23.
//We take it to be the same as the parameter kappa.
pub const RAW_SECURITY: u16 = 256;
pub const SECURITY: u16 = 32; //Used for arrays of bytes (32*8 = 256 bits).

//Statistical security parameter lambda_s from DKLs23.
pub const STAT_SECURITY: u16 = 80;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

}
