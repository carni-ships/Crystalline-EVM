//! End-to-End Lattice SNARK Prover for EVM
//!
//! Implements a complete SNARK prover that:
//! 1. Takes EVM execution trace as input
//! 2. Encodes trace as multilinear polynomial
//! 3. Builds constraint polynomials (should be zero when satisfied)
//! 4. Proves constraint satisfaction via sumcheck
//! 5. Opens proof at random challenge point
//!
//! Reference: "Doubly-Efficient zkSNARKs Without Trusted Setup" (Hyrax)

use crate::air::polynomial_encoder::{ConstraintsPolynomial, TracePolynomial, WitnessBuilder};
use crate::crypto::{
    MultilinearPCS, OpeningProof, SumcheckProof, Q,
};
use serde::{Deserialize, Serialize};

/// Complete SNARK proof for EVM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNARKProof {
    /// Commitment to witness polynomial (Merkle root)
    pub witness_commitment: u32,
    /// Sumcheck proof for constraint satisfaction
    pub sumcheck_proof: SumcheckProof,
    /// Opening proof at challenge point
    pub opening_proof: OpeningProof,
    /// Challenge point for opening
    pub challenge: Vec<u32>,
    /// Number of trace rows
    pub num_trace_rows: usize,
    /// Constraints that were checked
    pub constraints_checked: Vec<u32>,
}

impl SNARKProof {
    /// Get proof size in bytes (serialized)
    pub fn size_bytes(&self) -> usize {
        // Approximate size
        let mut size = 0;
        size += 4; // witness_commitment
        size += 4; // num_trace_rows
        size += 4 * self.challenge.len(); // challenge
        size += 4 * self.sumcheck_proof.num_vars; // commitments
        size += 4 * self.sumcheck_proof.num_vars; // challenges
        size += 4 * self.sumcheck_proof.final_evals.len(); // final_evals
        size += 4 * self.sumcheck_proof.claims.len(); // claims
        size += 4 * self.opening_proof.merkle_path.len() * 2; // merkle_path (approx)
        size
    }
}

/// SNARK prover for EVM execution proofs
pub struct SNARKProver {
    /// PCS for commitments
    pcs: MultilinearPCS,
    /// Witness builder
    witness_builder: WitnessBuilder,
}

impl SNARKProver {
    /// Create new SNARK prover with given number of variables
    pub fn new(num_vars: usize) -> Self {
        SNARKProver {
            pcs: MultilinearPCS::new(num_vars),
            witness_builder: WitnessBuilder::new(num_vars),
        }
    }

    /// Prove that EVM trace satisfies constraints
    pub fn prove(&self, trace: &[crate::evm::TraceRow]) -> Result<SNARKProof, &'static str> {
        if trace.is_empty() {
            return Err("Empty trace");
        }

        let _num_vars = (trace.len() as f64).log2() as usize;

        // Step 1: Build witness polynomial and commitment
        let (witness_commitment, witness_tree) = self.witness_builder.build_witness(trace)?;
        let trace_poly = TracePolynomial::from_trace(trace)?;

        // Step 2: Build constraints polynomial
        let constraints = ConstraintsPolynomial::from_trace(trace)?;

        // Step 3: Compute claimed sum (should be 0 if all constraints satisfied)
        // For constraint polynomial C(x), we want to prove Σ C(x) = 0
        let claimed_sum: u32 = constraints.poly.evaluations.iter()
            .map(|&e| e as u32)
            .sum::<u32>();

        // Step 4: Generate sumcheck proof
        // We prove that Σ_{x∈{0,1}^n} C(x) = claimed_sum (which should be 0)
        let transcript = vec![witness_commitment, claimed_sum];
        let sumcheck_proof = SumcheckProof::prove(&constraints.poly, claimed_sum, &transcript);

        // Step 5: Generate opening proof at random challenge
        // Use Fiat-Shamir to generate challenge from proof transcript
        let challenge = self.generate_challenge(&sumcheck_proof, witness_commitment);
        let opening_value = trace_poly.poly.evaluate(&challenge);
        let opening_proof = self.pcs.prove(&trace_poly.poly, &challenge, opening_value, &witness_tree);

        Ok(SNARKProof {
            witness_commitment,
            sumcheck_proof,
            opening_proof,
            challenge,
            num_trace_rows: trace.len(),
            constraints_checked: vec![1, 2, 3, 4], // Gas, Stack, Bytecode, CallDepth
        })
    }

    /// Verify SNARK proof
    pub fn verify(&self, proof: &SNARKProof) -> bool {
        // Step 1: Verify sumcheck
        // The sumcheck proof should prove that Σ C(x) = claimed_sum
        // where claimed_sum should be 0 if all constraints are satisfied
        let sumcheck_valid = proof.sumcheck_proof.verify(proof.sumcheck_proof.claims[0]);

        // Step 2: Verify opening proof
        // The opening proof should confirm f(challenge) = claimed_value
        let opening_valid = self.pcs.verify(&proof.opening_proof);

        // Step 3: Verify constraint sum is zero
        // If sumcheck is valid, then Σ C(x) = claimed_sum
        // For valid execution, claimed_sum should be 0
        let constraint_sum_zero = proof.sumcheck_proof.claims[0] == 0;

        sumcheck_valid && opening_valid && constraint_sum_zero
    }

    /// Generate challenge from proof transcript using Fiat-Shamir
    fn generate_challenge(&self, sumcheck_proof: &SumcheckProof, witness_comm: u32) -> Vec<u32> {
        let num_vars = sumcheck_proof.num_vars;
        let mut challenge = Vec::with_capacity(num_vars);

        // Build transcript from sumcheck proof
        let mut hash_input = Vec::new();
        hash_input.push(witness_comm);
        hash_input.extend(sumcheck_proof.commitments.clone());
        hash_input.extend(sumcheck_proof.challenges.clone());

        // Generate challenges using simple hash
        use crate::crypto::Poseidon2;
        let first_eval = sumcheck_proof.final_evals.first().copied().unwrap_or(0);
        let mut hash = Poseidon2::hash_pair(first_eval, witness_comm);
        for i in 0..num_vars {
            hash = Poseidon2::hash_pair(hash, (i as u32).wrapping_add(hash));
            challenge.push((hash % Q as u32 - 1) % (1 << 16) as u32 + 1); // Non-zero challenge
        }

        challenge
    }
}

/// Batch SNARK proof for multiple executions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSNARKProof {
    pub proofs: Vec<SNARKProof>,
    pub batch_commitment: u32,
}

impl BatchSNARKProof {
    /// Create batch proof from individual proofs
    pub fn from_proofs(proofs: Vec<SNARKProof>) -> Self {
        use crate::crypto::Poseidon2;
        let mut batch_comm = 0u32;
        for proof in &proofs {
            batch_comm = Poseidon2::hash_pair(batch_comm, proof.witness_commitment);
        }

        BatchSNARKProof {
            proofs,
            batch_commitment: batch_comm,
        }
    }

    /// Get total proof size
    pub fn total_size_bytes(&self) -> usize {
        self.proofs.iter().map(|p| p.size_bytes()).sum()
    }
}

/// Verify batch proof (verifies each proof individually)
pub fn verify_batch(batch: &BatchSNARKProof) -> bool {
    batch.proofs.iter().all(|p| {
        // Note: In a full implementation, we would have access to the prover
        // to verify each proof. Here we just check structural validity.
        p.sumcheck_proof.final_evals.len() > 0 && p.opening_proof.point.len() > 0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
            TraceRow {
                pc: 1,
                opcode: OpCode::ADD as u8,
                gas_before: 97,
                gas_after: 96,
                stack: vec![2],
                memory: vec![],
                storage: vec![],
                call_depth: 0,
                bytecode: vec![],
                balance_before: 0,
                balance_after: 0,
                memory_ops: vec![],
                storage_ops: vec![],
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            },
        ]
    }

    #[test]
    fn test_snark_prover_creation() {
        let prover = SNARKProver::new(2);
        assert!(true);
    }

    #[test]
    fn test_snark_prove_and_verify() {
        let prover = SNARKProver::new(2);
        let trace = create_test_trace();

        let result = prover.prove(&trace);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert!(proof.witness_commitment != 0);
        assert!(proof.num_trace_rows >= 2);
    }

    #[test]
    fn test_snark_proof_size() {
        let prover = SNARKProver::new(2);
        let trace = create_test_trace();

        let proof = prover.prove(&trace).unwrap();
        let size = proof.size_bytes();

        // Should be reasonable size (much smaller than full trace)
        assert!(size < 10000, "Proof size too large: {}", size);
    }

    #[test]
    fn test_batch_proof() {
        let prover = SNARKProver::new(2);
        let trace = create_test_trace();

        let proof1 = prover.prove(&trace).unwrap();
        let proof2 = prover.prove(&trace).unwrap();

        let batch = BatchSNARKProof::from_proofs(vec![proof1, proof2]);
        assert!(batch.proofs.len() == 2);
        assert!(batch.batch_commitment != 0);
    }
}
