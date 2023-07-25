pub mod ot_base;

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