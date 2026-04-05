//! Generic plonky2 → WHIR post-quantum verification pipeline.
//!
//! This crate provides a complete pipeline for generating and verifying
//! Plonky2 proofs using WHIR (hash-based, post-quantum) polynomial commitments
//! instead of FRI.
//!
//! # Components
//!
//! - **prover**: Core WHIR prover/verifier + on-chain data export
//! - **wrapper**: Generic `WrapperCircuit` for re-wrapping Plonky2 proofs
//! - **error**: Error types
//!
//! # Solidity Contracts
//!
//! The `contracts/` directory contains Solidity verifier contracts:
//! - `spongefish/SpongefishWhirVerify.sol` — WHIR polynomial commitment verification
//! - `Plonky2Verifier.sol` — Plonky2 constraint satisfaction check

pub mod error;
pub mod wrapper;

#[cfg(feature = "whir")]
pub mod prover;

#[cfg(feature = "whir")]
pub mod sumcheck;
