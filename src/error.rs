use thiserror::Error;

/// Error types for the plonky2-whir-verifier crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to prove wrapper circuit: {0}")]
    WrapperProofFailed(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;
