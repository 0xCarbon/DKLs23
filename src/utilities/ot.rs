pub mod ot_base;
pub mod ot_extension;

#[derive(Debug, Clone)]
pub struct ErrorOT {
    pub description: String,
}

impl ErrorOT {
    pub fn new(description: &str) -> ErrorOT {
        ErrorOT {
            description: String::from(description),
        }
    }
}