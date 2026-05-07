//! Lattice-Based Cryptography Explorations
//!
//! This module explores replacing traditional hash functions (Poseidon, Keccak) with
//! lattice-based alternatives for Merkle trees and Fiat-Shamir transformations.
//!
//! # Motivation
//!
//! - **Quantum Resistance**: Both Poseidon and Keccak are classical hashes.
//!   Lattice-based schemes are provably quantum-resistant under standard assumptions.
//! - **Unified Proof System**: Using the same underlying hardness assumption (LWE/SIS)
//!   throughout could simplify the security proof of the entire system.
//!
//! # Dilithium for Merkle Trees
//!
//! Traditional Merkle: hash(left || right) -> parent
//! Dilithium Merkle: Use signature as commitment
//!
//! ## Approach
//!
//! Instead of hashing two child nodes, we "commit" to them using a lattice-based
//! signature scheme. The signature over the concatenation of children serves as
//! the parent node. To verify, you verify the signature.
//!
//! However, full Dilithium signatures are ~2.6KB (Dilithium2), which is too large
//! for tree nodes. We need a more efficient lattice commitment.
//!
//! ## Better Approach: Lattice Commitment (M-LWE)
//!
//! Use Module-LWE based commitments similar to Kyber:
//! - Compress child nodes into a polynomial
//! - Sample random r, compute u = A*r + v (commitment)
//! - The commitment c = ENCODE(u) becomes the parent
//!
//! This is similar to how the Orion/Labrador prover already works!
//!
//! # Lattice-Based Fiat-Shamir
//!
//! Current: Poseidon2::hash_pair(challenge, data) for Fiat-Shamir
//! Goal: Replace with LWE-based hash that is quantum-resistant
//!
//! ## Approach: Lattice Hash (Based on Stehlé-Steinberg)
//!
//! ```ignore
//! H(m) = Round(A * m) mod q
//! ```
//!
//! Where A is a public random matrix, m is the message, and Round() compresses
//! the output to create a fixed-size digest.

use thiserror::Error;

pub mod dilithium_merkle;
pub mod lattice_fiat_shamir;
pub mod lattice_merkle;
pub mod benchmarks;

pub use dilithium_merkle::{LatticeMerkleCommitment, LatticeMerkleNode, build_lattice_merkle_tree};
pub use lattice_fiat_shamir::{LatticeHash, LatticeFiatShamirConfig};
pub use lattice_merkle::{
    build_lwe_merkle_tree, generate_membership_proof, get_root, verify_membership_proof,
    LatticeMerkleNode as LatticeMerkleNodeNew,
};
pub use benchmarks::run_all_benchmarks;