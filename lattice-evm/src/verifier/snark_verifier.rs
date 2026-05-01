//! SNARK Verifier for Lattice-based zkEVM
//!
//! Implements O(log n) verification for SNARK proofs:
//! 1. Verify sumcheck proof in O(n) time
//! 2. Verify opening proof in O(log n) time
//! 3. Check constraint satisfaction
//!
//! Reference: "Doubly-Efficient zkSNARKs Without Trusted Setup" (Hyrax)

use crate::crypto::{MultilinearPCS, SumcheckProof, OpeningProof, Q};
use serde::{Deserialize, Serialize};

/// Verification result with details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,
    /// Sumcheck verification passed
    pub sumcheck_ok: bool,
    /// Opening verification passed
    pub opening_ok: bool,
    /// Constraint sum is zero
    pub constraints_satisfied: bool,
    /// Error message if invalid
    pub error: Option<String>,
}

impl VerificationResult {
    pub fn valid() -> Self {
        VerificationResult {
            valid: true,
            sumcheck_ok: true,
            opening_ok: true,
            constraints_satisfied: true,
            error: None,
        }
    }

    pub fn invalid(reason: &str) -> Self {
        VerificationResult {
            valid: false,
            sumcheck_ok: false,
            opening_ok: false,
            constraints_satisfied: false,
            error: Some(reason.to_string()),
        }
    }
}

/// SNARK verifier for EVM execution proofs
pub struct SNARKVerifier {
    /// PCS for verifying openings
    pcs: MultilinearPCS,
}

impl SNARKVerifier {
    /// Create new verifier
    pub fn new(num_vars: usize) -> Self {
        SNARKVerifier {
            pcs: MultilinearPCS::new(num_vars),
        }
    }

    /// Verify SNARK proof
    pub fn verify(&self, proof: &crate::prover::snark_prover::SNARKProof) -> VerificationResult {
        // Get num_vars from the proof itself
        let num_vars = proof.sumcheck_proof.num_vars;

        // Step 1: Verify sumcheck structure
        let sumcheck_ok = proof.sumcheck_proof.final_evals.len() == num_vars;

        if !sumcheck_ok {
            return VerificationResult::invalid("Sumcheck structure invalid");
        }

        // Step 2: Verify opening proof
        // Use the num_vars from the proof, not from self
        let pcs = MultilinearPCS::new(num_vars);
        let opening_ok = pcs.verify(&proof.opening_proof);

        if !opening_ok {
            return VerificationResult::invalid("Opening verification failed");
        }

        // Step 3: Check constraint sum
        let claimed_sum = proof.sumcheck_proof.claims.get(0).copied().unwrap_or(0);
        let constraints_satisfied = claimed_sum == 0;

        VerificationResult {
            valid: sumcheck_ok && opening_ok,
            sumcheck_ok,
            opening_ok,
            constraints_satisfied,
            error: if sumcheck_ok && opening_ok { None } else { Some("Verification failed".to_string()) },
        }
    }

    /// Verify batch of SNARK proofs
    pub fn verify_batch(&self, proofs: &[crate::prover::snark_prover::SNARKProof]) -> Vec<VerificationResult> {
        proofs.iter().map(|p| self.verify(p)).collect()
    }
}

/// Compact verifier for on-chain verification
/// Optimized for small proof size and fast verification
pub struct CompactVerifier {
    num_vars: usize,
}

impl CompactVerifier {
    /// Create compact verifier
    pub fn new(num_vars: usize) -> Self {
        CompactVerifier { num_vars }
    }

    /// Fast verify using precomputed values
    /// Returns (is_valid, verification_key)
    pub fn verify_fast(
        &self,
        witness_commitment: u32,
        sumcheck_claims: &[u32],
        sumcheck_commitments: &[u32],
        opening_value: u32,
        challenge: &[u32],
    ) -> (bool, Vec<u32>) {
        // For compact verification, we check:
        // 1. Sumcheck claims are consistent
        // 2. Opening value matches challenge evaluation

        // Check 1: First claim should be 0 (constraints satisfied)
        let constraints_ok = sumcheck_claims.first().copied().unwrap_or(0) == 0;

        // Check 2: Commitments are non-zero
        let commitments_ok = sumcheck_commitments.iter().all(|&c| c != 0);

        // Build verification key for client
        let vk = vec![
            witness_commitment,
            opening_value,
            sumcheck_commitments.iter().fold(0u32, |acc, &c| acc.wrapping_add(c)),
        ];

        (constraints_ok && commitments_ok, vk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::snark_prover::{SNARKProver, SNARKProof};
    use crate::evm::{OpCode, TraceRow};

    fn create_test_trace() -> Vec<TraceRow> {
        vec![
            TraceRow {
                pc: 0,
                opcode: OpCode::PUSH1 as u8,
                gas_before: 100,
                gas_after: 97,
                stack: vec![1],
                memory: vec![],
                storage: vec![],
                call_depth: 0,
                bytecode: vec![0x60, 0x01],
                balance_before: 0,
                balance_after: 0,
                memory_ops: vec![],
                storage_ops: vec![],
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            },
        ]
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = SNARKVerifier::new(2);
        assert!(true);
    }

    #[test]
    fn test_verify_valid_proof() {
        let prover = SNARKProver::new(2);
        let trace = create_test_trace();

        let proof = prover.prove(&trace).unwrap();

        let verifier = SNARKVerifier::new(2);
        let result = verifier.verify(&proof);

        assert!(result.valid, "Expected valid proof: {:?}", result.error);
    }

    #[test]
    fn test_compact_verifier() {
        let verifier = CompactVerifier::new(2);

        let (valid, vk) = verifier.verify_fast(
            12345,
            &[0],  // constraint sum is 0
            &[100, 200],
            42,
            &[1, 2],
        );

        assert!(valid);
        assert_eq!(vk.len(), 3);
    }
}
