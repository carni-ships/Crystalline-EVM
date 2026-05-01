//! Labrador Protocol Implementation
//!
//! A lattice-based SNARK protocol for proving matrix-vector computations.
//! Uses RNS decomposition for modular arithmetic and ANE for acceleration.
//!
//! # Protocol Overview
//!
//! 1. **Commitment**: c = A·s mod q (using RNS + ANE)
//! 2. **Balanced Decomposition**: Decompose response using G⁻¹ function
//! 3. **Norm Check**: Verify ||u|| and ||v|| bounds (JL lemma)
//! 4. **Fiat-Shamir**: Generate challenges from transcript
//!
//! # Thread Safety
//! ANE operations in orion_latticezk.m are thread-safe (use IOSurface for data transfer).

use super::error::BackendError;
use orion_sys::{
    LatticeZKProvingKey, LatticeZKVerificationKey, LatticeZKProof,
    LATTICEZK_L,
    latticezk_prove, latticezk_verify,
    latticezk_keygen,
    latticezk_sample_short_vector,
};

/// Labrador prover for generating proofs
pub struct LabradorProver {
    /// Proving key (public for testing)
    pub pk: LatticeZKProvingKey,
}

impl LabradorProver {
    /// Create new prover from proving key
    pub fn new(pk: LatticeZKProvingKey) -> Self {
        LabradorProver { pk }
    }

    /// Create new prover with generated keys
    pub fn new_with_keygen(seed: &[u8; 32]) -> Self {
        let mut pk = LatticeZKProvingKey::default();
        let mut vk = LatticeZKVerificationKey::default();

        unsafe {
            latticezk_keygen(seed.as_ptr(), &mut pk, &mut vk);
        }

        LabradorProver { pk }
    }

    /// Generate proof for witness vector s using real FFI
    pub fn prove(&self, s: &[f32]) -> Result<LatticeZKProof, BackendError> {
        if s.len() != LATTICEZK_L as usize {
            return Err(BackendError::InvalidWitness(
                format!("Expected witness of length {}, got {}", LATTICEZK_L, s.len())
            ));
        }

        let mut proof = LatticeZKProof::default();

        // Time the FFI call
        let start = std::time::Instant::now();
        // Call the real Orion library prover (ANE is thread-safe via IOSurface)
        let success = unsafe {
            latticezk_prove(&self.pk, s.as_ptr(), &mut proof)
        };
        let elapsed = start.elapsed();

        if !success {
            return Err(BackendError::AneError("Labrador prove failed".to_string()));
        }

        tracing::debug!("Labrador prove completed in {:?}", elapsed);

        Ok(proof)
    }

    /// Generate proof from u64 witness vector (converts to f32)
    pub fn prove_from_u64(&self, s: &[u64]) -> Result<LatticeZKProof, BackendError> {
        let s_f32: Vec<f32> = s.iter().map(|&v| v as f32).collect();
        self.prove(&s_f32)
    }
}

/// Labrador verifier for checking proofs
pub struct LabradorVerifier {
    vk: LatticeZKVerificationKey,
}

impl LabradorVerifier {
    /// Create new verifier from verification key
    pub fn new(vk: LatticeZKVerificationKey) -> Self {
        LabradorVerifier { vk }
    }

    /// Verify a proof using real FFI
    pub fn verify(&self, proof: &LatticeZKProof) -> Result<bool, BackendError> {
        let valid = unsafe {
            latticezk_verify(&self.vk, proof)
        };

        tracing::debug!("Labrador verify: valid={}", valid);
        Ok(valid)
    }
}

/// Generate a random seed for key generation
pub fn generate_seed() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;

    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = ((nanos >> (i % 8)) & 0xFF) as u8;
    }
    seed
}

/// Sample a short vector for proving
pub fn sample_short_vector_f32(lambda: f32, l: usize) -> Vec<f32> {
    let mut s = vec![0f32; l];
    unsafe {
        latticezk_sample_short_vector(lambda, s.as_mut_ptr(), l as i32);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use orion_sys::{LATTICEZK_K, LATTICEZK_L, LATTICEZK_N, LATTICEZK_Q};

    #[test]
    fn test_keygen() {
        let seed = generate_seed();
        let prover = LabradorProver::new_with_keygen(&seed);

        assert_eq!(prover.pk.q, LATTICEZK_Q as u64);
        assert_eq!(prover.pk.k, LATTICEZK_K as i32);
        assert_eq!(prover.pk.l, LATTICEZK_L as i32);
    }

    #[test]
    #[ignore = "Requires ANE hardware"]
    fn test_prove_verify() {
        let seed = generate_seed();
        let prover = LabradorProver::new_with_keygen(&seed);

        // Get verification key from prover's pk (they're paired)
        let vk = LatticeZKVerificationKey {
            q: prover.pk.q,
            k: prover.pk.k,
            l: prover.pk.l,
            n: prover.pk.n,
        };

        let verifier = LabradorVerifier::new(vk);

        // Sample a short witness vector
        let s = sample_short_vector_f32(2.0, LATTICEZK_L as usize);
        let proof = prover.prove(&s).expect("ANE hardware required for proving");

        // Verify the proof
        let valid = verifier.verify(&proof).expect("Verification should succeed");
        assert!(valid, "Proof verification should succeed");
    }

    #[test]
    #[ignore = "Requires ANE hardware"]
    fn test_prove_verify_with_u64() {
        let seed = generate_seed();
        let prover = LabradorProver::new_with_keygen(&seed);

        let vk = LatticeZKVerificationKey {
            q: prover.pk.q,
            k: prover.pk.k,
            l: prover.pk.l,
            n: prover.pk.n,
        };

        let verifier = LabradorVerifier::new(vk);

        // Sample u64 witness and convert
        let s_u64: Vec<u64> = (0..LATTICEZK_L as usize)
            .map(|i| (i as u64 * 12345) % (LATTICEZK_Q as u64))
            .collect();

        let proof = prover.prove_from_u64(&s_u64).expect("ANE hardware required for proving");
        let valid = verifier.verify(&proof).expect("Verification should succeed");
        assert!(valid, "Proof verification should succeed with u64 input");
    }
}
