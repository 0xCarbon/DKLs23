pub mod base;
pub mod extension;

#[derive(Debug, Clone)]
pub struct ErrorOT {
    pub description: String,
}

impl ErrorOT {
    #[must_use]
    pub fn new(description: &str) -> ErrorOT {
        ErrorOT {
            description: String::from(description),
        }
    }
}
