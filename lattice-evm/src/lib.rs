//! Lattice EVM - Lattice-based zkEVM using Orion ANE primitives
//!
//! This implements a zkEVM using lattice assumptions (Dilithium-style)
//! with ANE acceleration for MatVec operations and GPU NTT.
//!
//! # Architecture
//!
//! - `evm`: EVM circuit adapted for lattice field (q=8383489)
//! - `air`: AIR (Algebraic Intermediate Representation) for EVM constraints
//! - `prover`: Labrador prover for generating proofs
//! - `verifier`: Verification using lattice commitment scheme

pub mod evm;
pub mod air;
pub mod prover;
pub mod verifier;
pub mod crypto;

pub use evm::LatticeEVM;
pub use air::{LatticeAIR, Constraint};
pub use prover::{Prover, full_prove, recursive_prove, parallel_prove};
pub use verifier::Verifier;

/// Lattice field modulus
pub const Q: u64 = 8383489;

/// Trace width for EVM circuit (k * l matrix dimensions)
pub const TRACE_WIDTH: usize = 4;

/// Polynomial degree
pub const DEGREE: usize = 256;