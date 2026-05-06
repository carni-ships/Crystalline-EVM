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
//!
//! # GPU Kernel Paths
//!
//! - `prove_batch_gpu`: Uses latticezk_prove_batch_gpu (MatVec → CPU RNS/CRT)
//! - `prove_batch_fused`: Uses matvec_rns_crt kernel (MatVec + RNS + CRT on GPU)

use super::error::BackendError;
use crate::gpu_matvec::GPUContext;
use orion_sys::{
    LatticeZKProvingKey, LatticeZKVerificationKey, LatticeZKProof,
    LATTICEZK_L,
    latticezk_prove, latticezk_prove_batch, latticezk_prove_batch_gpu, latticezk_verify,
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

        // SECURITY: Validate FFI output to detect corrupted/malformed proofs
        if !proof.is_valid() {
            return Err(BackendError::AneError(
                "Labrador prove returned invalid proof data - possible FFI corruption".to_string()
            ));
        }

        tracing::debug!("Labrador prove completed in {:?}", elapsed);

        Ok(proof)
    }

    /// Generate proof from u64 witness vector (converts to f32)
    pub fn prove_from_u64(&self, s: &[u64]) -> Result<LatticeZKProof, BackendError> {
        let s_f32: Vec<f32> = s.iter().map(|&v| v as f32).collect();
        self.prove(&s_f32)
    }

    /// Generate proofs for multiple witnesses in batch (auto-selects GPU/ANE)
    ///
    /// Automatically uses GPU batch proving if available, otherwise falls back to ANE.
    /// Amortizes the matrix expansion cost (latticezk_expand_a) across all witnesses.
    ///
    /// # Arguments
    /// * `witnesses` - Slice of witness vectors, each of length LATTICEZK_L (256)
    ///
    /// # Returns
    /// Vector of proofs, one per witness
    pub fn prove_batch(&self, witnesses: &[&[f32]]) -> Result<Vec<LatticeZKProof>, BackendError> {
        if witnesses.is_empty() {
            return Ok(Vec::new());
        }

        // SECURITY: Limit batch size to prevent memory exhaustion DoS
        const MAX_BATCH_SIZE: i32 = 10_000;
        let num_witnesses = witnesses.len() as i32;
        if num_witnesses > MAX_BATCH_SIZE {
            return Err(BackendError::InvalidWitness(
                format!("Batch size {} exceeds maximum {} - potential DoS prevention",
                    num_witnesses, MAX_BATCH_SIZE)
            ));
        }

        // Validate all witnesses have correct length
        for (i, witness) in witnesses.iter().enumerate() {
            if witness.len() != LATTICEZK_L as usize {
                return Err(BackendError::InvalidWitness(
                    format!("Witness {}: expected length {}, got {}",
                        i, LATTICEZK_L, witness.len())
                ));
            }
        }

        let mut proofs = vec![LatticeZKProof::default(); num_witnesses as usize];

        // Flatten witnesses into batch format: [witness0_l0, witness0_l1, ..., witness1_l0, ...]
        let mut s_batch: Vec<f32> = Vec::with_capacity((num_witnesses as usize) * (LATTICEZK_L as usize));
        for witness in witnesses {
            s_batch.extend_from_slice(witness);
        }

        // Try GPU batch first, fall back to ANE if GPU unavailable
        let start = std::time::Instant::now();
        let success = unsafe {
            // Try GPU path first - it has TRUE parallelism
            if GPUContext::available() {
                latticezk_prove_batch_gpu(
                    &self.pk,
                    s_batch.as_ptr(),
                    num_witnesses,
                    proofs.as_mut_ptr(),
                )
            } else {
                // Fall back to ANE (serialized per witness)
                latticezk_prove_batch(
                    &self.pk,
                    s_batch.as_ptr(),
                    num_witnesses,
                    proofs.as_mut_ptr(),
                )
            }
        };
        let elapsed = start.elapsed();

        if !success {
            return Err(BackendError::AneError("Labrador batch prove failed".to_string()));
        }

        // SECURITY: Validate all proofs returned by FFI
        for (i, proof) in proofs.iter().enumerate() {
            if !proof.is_valid() {
                return Err(BackendError::AneError(
                    format!("Labrador batch prove returned invalid proof at index {} - possible FFI corruption", i)
                ));
            }
        }

        tracing::debug!("Labrador batch prove completed {} proofs in {:?}", num_witnesses, elapsed);

        Ok(proofs)
    }

    /// Generate proofs for multiple witnesses using GPU batch (force GPU path)
    ///
    /// Uses orion_gpu_matvec_batch for TRUE PARALLEL MatVec processing.
    /// Returns error if GPU is not available.
    ///
    /// # Arguments
    /// * `witnesses` - Slice of witness vectors, each of length LATTICEZK_L (256)
    ///
    /// # Returns
    /// Vector of proofs, one per witness
    pub fn prove_batch_gpu(&self, witnesses: &[&[f32]]) -> Result<Vec<LatticeZKProof>, BackendError> {
        if witnesses.is_empty() {
            return Ok(Vec::new());
        }

        // Validate all witnesses have correct length
        for (i, witness) in witnesses.iter().enumerate() {
            if witness.len() != LATTICEZK_L as usize {
                return Err(BackendError::InvalidWitness(
                    format!("Witness {}: expected length {}, got {}",
                        i, LATTICEZK_L, witness.len())
                ));
            }
        }

        // Check GPU availability
        if !GPUContext::available() {
            return Err(BackendError::AneError("GPU not available".to_string()));
        }

        let num_witnesses = witnesses.len() as i32;
        let mut proofs = vec![LatticeZKProof::default(); num_witnesses as usize];

        // Flatten witnesses into batch format
        let mut s_batch: Vec<f32> = Vec::with_capacity((num_witnesses as usize) * (LATTICEZK_L as usize));
        for witness in witnesses {
            s_batch.extend_from_slice(witness);
        }

        // Time the GPU FFI call
        let start = std::time::Instant::now();
        let success = unsafe {
            latticezk_prove_batch_gpu(
                &self.pk,
                s_batch.as_ptr(),
                num_witnesses,
                proofs.as_mut_ptr(),
            )
        };
        let elapsed = start.elapsed();

        if !success {
            return Err(BackendError::AneError("Labrador GPU batch prove failed".to_string()));
        }

        tracing::debug!("Labrador GPU batch prove completed {} proofs in {:?}", num_witnesses, elapsed);

        Ok(proofs)
    }

    /// Generate proofs using fully GPU-accelerated path (no ANE)
///
/// This is the ultimate GPU path: seed → A (GPU) → A*s + RNS + CRT (GPU)
/// No CPU or ANE involved in the core math.
///
/// This method calls `latticezk_prove_batch_fused` which:
/// 1. Expands A from seed on GPU (via expand_a_from_seed kernel)
/// 2. Computes MatVec + RNS decomposition + CRT reconstruction on GPU
/// 3. Generates Fiat-Shamir proofs on CPU
///
/// # Arguments
/// * `witnesses` - Slice of witness vectors, each of length LATTICEZK_L (256)
///
/// # Returns
/// Vector of proofs, one per witness
pub fn prove_batch_fused(&self, witnesses: &[&[f32]]) -> Result<Vec<LatticeZKProof>, BackendError> {
    use orion_sys::latticezk_prove_batch_fused;

    if witnesses.is_empty() {
        return Ok(Vec::new());
    }

    // Validate all witnesses have correct length
    for (i, witness) in witnesses.iter().enumerate() {
        if witness.len() != LATTICEZK_L as usize {
            return Err(BackendError::InvalidWitness(
                format!("Witness {}: expected length {}, got {}",
                    i, LATTICEZK_L, witness.len())
            ));
        }
    }

    let num_witnesses = witnesses.len() as i32;
    let mut proofs = vec![LatticeZKProof::default(); num_witnesses as usize];

    // Flatten witnesses into batch format
    let s_batch: Vec<f32> = witnesses.iter()
        .flat_map(|w| w.iter().copied())
        .collect();

    // Time the GPU FFI call
    let start = std::time::Instant::now();
    let success = unsafe {
        latticezk_prove_batch_fused(
            &self.pk,
            s_batch.as_ptr(),
            num_witnesses,
            proofs.as_mut_ptr(),
        )
    };
    let elapsed = start.elapsed();

    if !success {
        return Err(BackendError::AneError("Labrador fused batch prove failed".to_string()));
    }

    tracing::debug!("Labrador fused batch prove completed {} proofs in {:?}", num_witnesses, elapsed);

    Ok(proofs)
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

    #[test]
    #[ignore = "Requires ANE hardware"]
    fn test_prove_batch() {
        let seed = generate_seed();
        let prover = LabradorProver::new_with_keygen(&seed);

        let vk = LatticeZKVerificationKey {
            q: prover.pk.q,
            k: prover.pk.k,
            l: prover.pk.l,
            n: prover.pk.n,
        };

        let verifier = LabradorVerifier::new(vk);

        // Create 4 witnesses
        let witnesses: Vec<Vec<f32>> = (0..4)
            .map(|i| {
                (0..LATTICEZK_L as usize)
                    .map(|j| ((i as f32 + 1.0) * j as f32) % 8.0)
                    .collect()
            })
            .collect();

        let witness_refs: Vec<&[f32]> = witnesses.iter().map(|v| v.as_slice()).collect();

        // Batch prove all witnesses
        let proofs = prover.prove_batch(&witness_refs)
            .expect("ANE hardware required for batch proving");

        // Verify all proofs
        for (i, proof) in proofs.iter().enumerate() {
            let valid = verifier.verify(proof)
                .expect("Verification should succeed");
            assert!(valid, "Batch proof {} verification should succeed", i);
        }
    }
}
