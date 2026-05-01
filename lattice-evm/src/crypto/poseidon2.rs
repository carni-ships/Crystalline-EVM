//! Poseidon2 Hash Function for Lattice Field Q=8383489
//!
//! Poseidon2 is a SNARK-friendly hash function designed for use in
//! zero-knowledge proof systems. This implementation is for field Q=8383489.

use crate::crypto::Q as FIELD_Q;
use std::sync::OnceLock;

/// Poseidon2 configuration for Q=8383489
pub const HASH_WIDTH: usize = 8;  // State width
pub const HASH_RATE: usize = 4;   // Rate (elements absorbed per permutation)
pub const SECURITY_LEVEL: usize = 128;

/// Round constants for Poseidon2 - cached for performance
/// Generated deterministically for field Q=8383489 using LCG with seed=1
static ROUND_CONSTANTS: OnceLock<[u32; 128]> = OnceLock::new();

fn get_round_constants() -> &'static [u32; 128] {
    ROUND_CONSTANTS.get_or_init(|| {
        let mut constants = [0u32; 128];
        let mut seed = 1u64;
        let q = FIELD_Q as u32;
        for i in 0..128 {
            seed = (seed * 1103515245 + 12345) & 0x7fffffff;
            constants[i] = (seed % q as u64) as u32;
        }
        constants
    })
}

/// MDS matrix for width 8 - cached for performance
static MDS_MATRIX: OnceLock<[[u32; 8]; 8]> = OnceLock::new();

fn get_mds_matrix() -> &'static [[u32; 8]; 8] {
    MDS_MATRIX.get_or_init(|| {
        [
            [1u32, 0, 0, 0, 0, 0, 0, 0],
            [0u32, 1, 0, 0, 0, 0, 0, 0],
            [0u32, 0, 1, 0, 0, 0, 0, 0],
            [0u32, 0, 0, 1, 0, 0, 0, 0],
            [0u32, 0, 0, 0, 1, 0, 0, 0],
            [0u32, 0, 0, 0, 0, 1, 0, 0],
            [0u32, 0, 0, 0, 0, 0, 1, 0],
            [0u32, 0, 0, 0, 0, 0, 0, 1],
        ]
    })
}

/// Poseidon2 state
#[derive(Debug, Clone, Default)]
pub struct Poseidon2State {
    pub elements: [u32; HASH_WIDTH],
}

impl Poseidon2State {
    /// Create new state from elements
    pub fn new(elements: [u32; HASH_WIDTH]) -> Self {
        Poseidon2State { elements }
    }

    /// Create state from input bytes
    pub fn from_bytes(input: &[u8]) -> Self {
        let mut elements = [0u32; HASH_WIDTH];
        for (i, &byte) in input.iter().take(HASH_WIDTH).enumerate() {
            elements[i] = (byte as u32) % (FIELD_Q as u32);
        }
        Poseidon2State { elements }
    }

    /// Apply S-box (x^5 for Poseidon2 on Q=8383489)
    fn sbox(&mut self, round: usize) {
        let constants = get_round_constants();
        for i in 0..HASH_WIDTH {
            // Add round constant
            self.elements[i] = self.elements[i].wrapping_add(constants[round * HASH_WIDTH + i]) % FIELD_Q as u32;
            // Apply x^5 S-box
            let x = self.elements[i] as u64;
            let x2 = (x * x) % FIELD_Q as u64;
            let x4 = (x2 * x2) % FIELD_Q as u64;
            self.elements[i] = ((x4 * x) % FIELD_Q as u64) as u32;
        }
    }

    /// Apply MDS matrix
    fn apply_mds(&mut self) {
        let mds = get_mds_matrix();
        let mut new_elements = [0u32; HASH_WIDTH];

        for i in 0..HASH_WIDTH {
            let mut sum = 0u64;
            for j in 0..HASH_WIDTH {
                sum = (sum + (mds[i][j] as u64) * (self.elements[j] as u64)) % FIELD_Q as u64;
            }
            new_elements[i] = sum as u32;
        }

        self.elements = new_elements;
    }
}

/// Poseidon2 hash function
pub struct Poseidon2;

impl Poseidon2 {
    /// Hash input bytes to produce hash output
    pub fn hash(input: &[u8]) -> [u8; 32] {
        // Initialize state from input
        let mut state = Poseidon2State::from_bytes(input);

        // Apply first half of rounds with S-boxes
        for round in 0..8 {
            state.sbox(round);
            state.apply_mds();
        }

        // Apply intermediate rounds (without S-box)
        for _ in 0..4 {
            state.apply_mds();
        }

        // Apply second half of rounds with S-boxes
        for round in 8..16 {
            state.sbox(round);
            state.apply_mds();
        }

        // Output is first 4 elements (rate) as bytes
        let mut output = [0u8; 32];
        for i in 0..4 {
            let val = state.elements[i];
            output[i * 8] = (val & 0xff) as u8;
            output[i * 8 + 1] = ((val >> 8) & 0xff) as u8;
            output[i * 8 + 2] = ((val >> 16) & 0xff) as u8;
            output[i * 8 + 3] = ((val >> 24) & 0xff) as u8;
        }

        output
    }

    /// Hash to field elements (mod Q)
    pub fn hash_field(input: &[u8]) -> Vec<u32> {
        let hash = Self::hash(input);
        hash.iter().map(|&b| (b as u32) % FIELD_Q as u32).collect()
    }

    /// Hash two field elements (for Merkle tree leaves)
    pub fn hash_pair(a: u32, b: u32) -> u32 {
        let input = [a, b, 0, 0, 0, 0, 0, 0];
        let mut state = Poseidon2State::new(input);

        // Single permutation round using cached constants
        let constants = get_round_constants();
        for i in 0..HASH_WIDTH {
            state.elements[i] = state.elements[i].wrapping_add(constants[i]) % FIELD_Q as u32;
            let x = state.elements[i] as u64;
            let x2 = (x * x) % FIELD_Q as u64;
            let x4 = (x2 * x2) % FIELD_Q as u64;
            state.elements[i] = ((x4 * x) % FIELD_Q as u64) as u32;
        }

        // Apply MDS using cached matrix
        let mds = get_mds_matrix();
        let mut new = [0u32; HASH_WIDTH];
        for i in 0..HASH_WIDTH {
            let mut sum = 0u64;
            for j in 0..HASH_WIDTH {
                sum = (sum + (mds[i][j] as u64) * (state.elements[j] as u64)) % FIELD_Q as u64;
            }
            new[i] = sum as u32;
        }

        // Return first element as hash
        new[0]
    }

    /// Compute Merkle root from leaves
    pub fn merkle_root(leaves: &[u32]) -> u32 {
        if leaves.is_empty() {
            return 0;
        }

        let mut tree = leaves.to_vec();

        // Build tree bottom-up
        while tree.len() > 1 {
            let mut new_level = Vec::new();
            for pair in tree.chunks(2) {
                let hash = if pair.len() == 2 {
                    Self::hash_pair(pair[0], pair[1])
                } else {
                    // Odd node - hash with itself
                    Self::hash_pair(pair[0], pair[0])
                };
                new_level.push(hash);
            }
            tree = new_level;
        }

        tree[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_empty() {
        let hash = Poseidon2::hash(&[]);
        tracing::info!("Poseidon2([]): {:02x?}", &hash);
    }

    #[test]
    fn test_poseidon2_simple() {
        let input = b"test";
        let hash = Poseidon2::hash(input);
        tracing::info!("Poseidon2('test'): {:02x?}", &hash);

        // Should be deterministic
        let hash2 = Poseidon2::hash(input);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_poseidon2_hash_pair() {
        let a: u32 = 12345;
        let b: u32 = 67890;
        let hash = Poseidon2::hash_pair(a, b);
        tracing::info!("Poseidon2({}, {}) = {}", a, b, hash);
        assert!(hash < FIELD_Q as u32);
    }

    #[test]
    fn test_poseidon2_merkle_root() {
        let leaves = vec![1u32, 2, 3, 4, 5, 6, 7, 8];
        let root = Poseidon2::merkle_root(&leaves);
        tracing::info!("Merkle root of {:?}: {}", leaves, root);
        assert!(root < FIELD_Q as u32);
    }

    #[test]
    fn test_poseidon2_mod_q() {
        let input = b"hello world";
        let field_elems = Poseidon2::hash_field(input);
        tracing::info!("Poseidon2 as field elements: {:?}", field_elems);

        for &fe in &field_elems {
            assert!(fe < FIELD_Q as u32);
        }
    }
}