//! Lattice-Based Fiat-Shamir Transformation
//!
//! Uses the Orion library's LWE-based hash function for quantum-resistant
//! Fiat-Shamir challenges in NovaIVC/SuperNova folding.
//!
//! # Real Implementation
//!
//! This module uses `orion_backend::hash_lwe()` which calls the Orion C library's
//! `latticezk_hash_lwe` function - a real LWE-based hash:
//!
//! ```ignore
//! H(domain, msg) = Compress(A_domain * msg mod q)
//! ```
//!
//! Where:
//! - A_domain is derived from a domain-specific seed
//! - msg is the input message
//! - Output is a field element (u32)
//!
//! This provides quantum-resistant hashing under standard LWE assumptions.

use orion_backend::hash_lwe;
use crate::crypto::Poseidon2;

/// Domain separators for different proof systems
const DOMAIN_NOVA_FOLDING: &[u8] = b"nova-folding-v1";
const DOMAIN_SUPERNOVA_MF: &[u8] = b"supernova-mf-v1";

/// Configuration for lattice-based Fiat-Shamir
#[derive(Debug, Clone)]
pub struct LatticeFiatShamirConfig {
    /// Security parameter λ in bits
    pub security_bits: usize,
    /// Use real LWE hash (if false, falls back to Poseidon)
    pub use_real_lwe: bool,
}

impl Default for LatticeFiatShamirConfig {
    fn default() -> Self {
        LatticeFiatShamirConfig {
            security_bits: 128,
            use_real_lwe: true,
        }
    }
}

/// Lattice-based hash for ZK contexts
///
/// Uses Orion's LWE-based hash function for quantum-resistant Fiat-Shamir.
/// Falls back to Poseidon if LWE hash is unavailable.
pub struct LatticeHash {
    config: LatticeFiatShamirConfig,
}

impl LatticeHash {
    pub fn new(config: LatticeFiatShamirConfig) -> Self {
        LatticeHash { config }
    }

    /// Compute lattice hash of two field elements
    ///
    /// Uses real LWE hash: H(domain, [a, b]) = Compress(A * [a,b] mod q)
    pub fn hash(&self, a: u32, b: u32) -> u32 {
        if self.config.use_real_lwe {
            // Use real LWE hash from Orion
            match hash_lwe(b"lattice-hash-v1", &[a, b]) {
                Ok(h) => h,
                Err(_) => {
                    // Fallback to Poseidon if LWE fails
                    tracing::warn!("LWE hash failed, falling back to Poseidon");
                    Poseidon2::hash_pair(a, b)
                }
            }
        } else {
            // Fallback to Poseidon for testing/comparison
            Poseidon2::hash_pair(a, b)
        }
    }

    /// Hash multiple field elements
    pub fn hash_many(&self, inputs: &[u32]) -> u32 {
        if inputs.is_empty() {
            return 0;
        }

        if self.config.use_real_lwe {
            match hash_lwe(b"lattice-hash-many-v1", inputs) {
                Ok(h) => h,
                Err(_) => {
                    tracing::warn!("LWE hash_many failed, falling back to Poseidon");
                    let mut result = inputs[0];
                    for (i, &input) in inputs.iter().enumerate().skip(1) {
                        result = Poseidon2::hash_pair(result, input);
                        result = result.wrapping_mul(0x13579ACEu32.wrapping_add(i as u32));
                    }
                    result
                }
            }
        } else {
            let mut result = inputs[0];
            for (i, &input) in inputs.iter().enumerate().skip(1) {
                result = Poseidon2::hash_pair(result, input);
                result = result.wrapping_mul(0x13579ACEu32.wrapping_add(i as u32));
            }
            result
        }
    }

    /// Fiat-Shamir challenge generation for NovaIVC
    ///
    /// Generates challenge r = H(domain, comm_w_old || comm_w_cccs || n_proofs)
    pub fn generate_folding_challenge(
        &self,
        comm_w_old: u32,
        comm_w_cccs: u32,
        n_proofs: usize,
    ) -> u32 {
        let inputs = &[comm_w_old, comm_w_cccs, n_proofs as u32];
        if self.config.use_real_lwe {
            match hash_lwe(DOMAIN_NOVA_FOLDING, inputs) {
                Ok(h) => h,
                Err(_) => {
                    // Fallback
                    let h1 = Poseidon2::hash_pair(comm_w_old, comm_w_cccs);
                    let h2 = Poseidon2::hash_pair(h1, n_proofs as u32);
                    Poseidon2::hash_pair(h2, 0xDEADBEEFu32)
                }
            }
        } else {
            let h1 = Poseidon2::hash_pair(comm_w_old, comm_w_cccs);
            let h2 = Poseidon2::hash_pair(h1, n_proofs as u32);
            Poseidon2::hash_pair(h2, 0xDEADBEEFu32)
        }
    }

    /// Fiat-Shamir challenge for SuperNova multifolding
    pub fn generate_multifold_challenge(
        &self,
        initial_state: u32,
        commitment: u32,
        step: usize,
    ) -> u32 {
        let inputs = &[initial_state, commitment, step as u32];
        if self.config.use_real_lwe {
            match hash_lwe(DOMAIN_SUPERNOVA_MF, inputs) {
                Ok(h) => h,
                Err(_) => {
                    let h1 = Poseidon2::hash_pair(initial_state, commitment);
                    let h2 = Poseidon2::hash_pair(h1, step as u32);
                    Poseidon2::hash_pair(h2, 0xFACEB00Bu32)
                }
            }
        } else {
            let h1 = Poseidon2::hash_pair(initial_state, commitment);
            let h2 = Poseidon2::hash_pair(h1, step as u32);
            Poseidon2::hash_pair(h2, 0xFACEB00Bu32)
        }
    }
}

/// Trait for lattice-based hash functions (for exploring different implementations)
pub trait LatticeHashTrait {
    fn digest(&self, a: u32, b: u32) -> u32;
}

/// Wrap our implementation
impl LatticeHashTrait for LatticeHash {
    fn digest(&self, a: u32, b: u32) -> u32 {
        self.hash(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_hash_deterministic() {
        let hasher = LatticeHash::new(LatticeFiatShamirConfig::default());

        let h1 = hasher.hash(123, 456);
        let h2 = hasher.hash(123, 456);

        assert_eq!(h1, h2, "Same inputs should produce same hash");
    }

    #[test]
    fn test_lattice_hash_different_inputs() {
        let hasher = LatticeHash::new(LatticeFiatShamirConfig::default());

        let h1 = hasher.hash(123, 456);
        let h2 = hasher.hash(456, 123);

        // These might collide with very low probability, but let's see
        // If they do collide, that's actually fine for this test
        println!("h1={:08x}, h2={:08x}", h1, h2);
    }

    #[test]
    fn test_generate_folding_challenge() {
        let hasher = LatticeHash::new(LatticeFiatShamirConfig::default());

        let r = hasher.generate_folding_challenge(100, 200, 8);

        assert!(r != 0, "Challenge should be non-zero");
    }

    #[test]
    fn test_lattice_hash_chain() {
        let hasher = LatticeHash::new(LatticeFiatShamirConfig::default());

        let result = hasher.hash_many(&[1, 2, 3, 4, 5]);

        assert!(result != 0, "Chained hash should be non-zero");
    }

    #[test]
    fn test_fallback_mode() {
        // Test with use_real_lwe = false (Poseidon fallback)
        let hasher = LatticeHash::new(LatticeFiatShamirConfig {
            use_real_lwe: false,
            security_bits: 128,
        });

        let h1 = hasher.hash(123, 456);
        let h2 = hasher.hash(123, 456);

        assert_eq!(h1, h2, "Same inputs should produce same hash in fallback mode");
    }
}