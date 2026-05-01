//! Error types for Orion Backend

use thiserror::Error;

/// Main backend error type
#[derive(Error, Debug)]
pub enum BackendError {
    #[error("Failed to parse ACIR: {0}")]
    ParseError(String),

    #[error("Unsupported opcode: {0}")]
    UnsupportedOpcode(String),

    #[error("Brillig execution failed: {0}")]
    BrilligError(String),

    #[error("ANE operation failed: {0}")]
    AneError(String),

    #[error("GPU operation failed: {0}")]
    GpuError(String),

    #[error("FFI error: {0}")]
    FfiError(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::ParseError(e.to_string())
    }
}

impl From<serde_json::Error> for BackendError {
    fn from(e: serde_json::Error) -> Self {
        BackendError::ParseError(e.to_string())
    }
}