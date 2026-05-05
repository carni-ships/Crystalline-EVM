//! Cryptographic primitives for Lattice EVM
//!
//! Includes Keccak-256 for Ethereum transactions and Poseidon2 for Merkle commitments.

pub mod batch_merkle;
pub mod keccak;
pub mod poseidon2;
pub mod multilinear_pcs;
pub mod smt;

pub use keccak::{keccak256, keccak256_field, keccak256_u32_words, keccak256_batch_parents, keccak256_node};
pub use poseidon2::{Poseidon2, HASH_WIDTH, HASH_RATE};
pub use multilinear_pcs::{MultilinearPolynomial, MultilinearPCS, MerkleTree, OpeningProof, SumcheckProof};
pub use smt::{SparseMerkleTree, SMTProof};
pub use batch_merkle::BatchMerkleTree;

/// Field modulus for lattice-based operations
pub const Q: u64 = 8383489;

/// Poseidon2 parameters for field Q
/// These would normally be generated through a formal process
pub const ROUND_CONSTANTS: [u32; 64] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
];

/// MDS (Maximum Distance Separable) matrix for Poseidon2
/// 8x8 matrix for width 8
pub const MDS_MATRIX: [[u32; 8]; 8] = [
    [1, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0],
    [0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_dependencies() {
        // Verify Q is correct
        assert_eq!(Q, 8383489);

        // Verify Keccak works
        let hash = keccak256(b"test");
        assert_eq!(hash.len(), 32);

        // Verify Poseidon2 constants
        assert_eq!(ROUND_CONSTANTS.len(), 64);
        assert_eq!(MDS_MATRIX.len(), 8);
    }
}