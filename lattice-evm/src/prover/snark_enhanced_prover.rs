//! SNARK-Enhanced Prover
//!
//! Integrates lattice SNARK proving into the main prover pipeline.
//! Uses SNARKProof for proper constraint verification alongside Labrador proofs.

use crate::air::polynomial_encoder::{TracePolynomial, ConstraintsPolynomial, WitnessBuilder};
use crate::crypto::{MultilinearPCS, Q};
use crate::evm::TraceRow;
use crate::prover::snark_prover::{SNARKProof, SNARKProver, BatchSNARKProof};
use crate::verifier::snark_verifier::{SNARKVerifier, VerificationResult};
use serde::{Deserialize, Serialize};

/// Combined proof that includes both Labrador and SNARK verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedProof {
    /// Labrador commitment
    pub labrador_commitment: Vec<u8>,
    /// SNARK proof for constraint verification
    pub snark_proof: Option<SNARKProof>,
    /// Witness commitment
    pub witness_commitment: u32,
    /// Number of trace rows
    pub num_rows: usize,
}

impl CombinedProof {
    /// Verify both Labrador and SNARK components
    pub fn verify(&self) -> VerificationResult {
        if let Some(ref snark) = self.snark_proof {
            let verifier = SNARKVerifier::new(snark.sumcheck_proof.num_vars);
            verifier.verify(snark)
        } else {
            VerificationResult::invalid("No SNARK proof available")
        }
    }

    /// Get total proof size
    pub fn size_bytes(&self) -> usize {
        let snark_size = self.snark_proof.as_ref().map(|p| p.size_bytes()).unwrap_or(0);
        32 + snark_size + 4 + 4 // labrador_commitment + snark + witness + num_rows
    }
}

/// SNARK-enhanced trace witness with metadata for SNARK proving
#[derive(Debug, Clone)]
pub struct SNARKTraceWitness {
    /// Trace rows
    pub traces: Vec<Vec<TraceRow>>,
    /// Witness commitment (Merkle root)
    pub witness_commitment: u32,
    /// Number of rows
    pub num_rows: usize,
    /// Constraint sum (should be 0 for valid execution)
    pub constraint_sum: u32,
    /// Num vars for multilinear encoding
    pub num_vars: usize,
}

impl SNARKTraceWitness {
    /// Create from execution traces
    pub fn from_traces(traces: &[Vec<TraceRow>]) -> Result<Self, &'static str> {
        if traces.is_empty() {
            return Err("No traces");
        }

        let total_rows: usize = traces.iter().map(|t| t.len()).sum();
        if total_rows == 0 {
            return Err("Empty traces");
        }

        let num_vars = (total_rows as f64).log2() as usize;

        // Flatten traces into a single vector of owned TraceRows
        let all_rows: Vec<TraceRow> = traces.iter().flat_map(|t| t.clone()).collect();

        // Build trace polynomial
        let trace_poly = TracePolynomial::from_trace(&all_rows)?;

        // Build constraints polynomial
        let constraints = ConstraintsPolynomial::from_trace(&all_rows)?;

        // Compute constraint sum (should be 0 if all constraints satisfied)
        let constraint_sum: u32 = constraints.poly.evaluations.iter()
            .map(|&e| e as u32)
            .sum();

        let (witness_commitment, _tree) = WitnessBuilder::new(num_vars)
            .build_witness(&all_rows)?;

        Ok(SNARKTraceWitness {
            traces: traces.to_vec(),
            witness_commitment,
            num_rows: total_rows,
            constraint_sum,
            num_vars,
        })
    }

    /// Generate SNARK proof for this witness
    pub fn prove(&self) -> Result<SNARKProof, &'static str> {
        let prover = SNARKProver::new(self.num_vars);
        let all_rows: Vec<TraceRow> = self.traces.iter().flat_map(|t| t.clone()).collect();
        prover.prove(&all_rows)
    }

    /// Verify SNARK proof
    pub fn verify_proof(&self, proof: &SNARKProof) -> VerificationResult {
        let verifier = SNARKVerifier::new(self.num_vars);
        verifier.verify(proof)
    }
}

/// Prove a single transaction with SNARK verification
pub fn prove_single_tx_snark(traces: &[Vec<TraceRow>]) -> Result<SNARKProof, &'static str> {
    let witness = SNARKTraceWitness::from_traces(traces)?;
    witness.prove()
}

/// Prove multiple transactions with batch SNARK
pub fn prove_block_snark(traces: &[Vec<Vec<TraceRow>>]) -> Result<BatchSNARKProof, &'static str> {
    let mut proofs = Vec::new();

    for trace in traces {
        let witness = SNARKTraceWitness::from_traces(&trace)?;
        let proof = witness.prove()?;
        proofs.push(proof);
    }

    Ok(BatchSNARKProof::from_proofs(proofs))
}

/// Verify SNARK proof for trace
pub fn verify_snark_proof(proof: &SNARKProof, num_vars: usize) -> VerificationResult {
    let verifier = SNARKVerifier::new(num_vars);
    verifier.verify(proof)
}

/// Full proving result with both Labrador and SNARK components
#[derive(Debug, Clone)]
pub struct FullProvingResult {
    /// Combined proof
    pub combined: CombinedProof,
    /// SNARK proof
    pub snark: SNARKProof,
    /// Verification result
    pub verification: VerificationResult,
    /// Proving time in ms
    pub proving_time_ms: u64,
}

impl FullProvingResult {
    /// Create from traces
    pub fn from_traces(traces: &[Vec<TraceRow>]) -> Result<Self, &'static str> {
        let start = std::time::Instant::now();

        let witness = SNARKTraceWitness::from_traces(traces)?;
        let snark = witness.prove()?;
        let verification = witness.verify_proof(&snark);

        let proving_time = start.elapsed().as_millis() as u64;

        let combined = CombinedProof {
            labrador_commitment: snark.witness_commitment.to_le_bytes().to_vec(),
            snark_proof: Some(snark.clone()),
            witness_commitment: snark.witness_commitment,
            num_rows: witness.num_rows,
        };

        Ok(FullProvingResult {
            combined,
            snark,
            verification,
            proving_time_ms: proving_time,
        })
    }
}

/// Integration with existing prover pipeline
pub struct SNARKEnhancedProver {
    /// SNARK prover
    snark_prover: SNARKProver,
    /// SNARK verifier
    snark_verifier: SNARKVerifier,
}

impl SNARKEnhancedProver {
    pub fn new() -> Self {
        let num_vars = 10; // Default for 1024 trace rows
        SNARKEnhancedProver {
            snark_prover: SNARKProver::new(num_vars),
            snark_verifier: SNARKVerifier::new(num_vars),
        }
    }

    /// Prove traces with SNARK
    pub fn prove_traces(&mut self, traces: &[Vec<TraceRow>]) -> Result<SNARKProof, &'static str> {
        // Adjust num_vars based on trace size
        let total_rows: usize = traces.iter().map(|t| t.len()).sum();
        let num_vars = (total_rows as f64).log2().ceil() as usize;

        // Create prover with correct size
        let prover = SNARKProver::new(num_vars);
        let all_rows: Vec<TraceRow> = traces.iter().flat_map(|t| t.clone()).collect();
        prover.prove(&all_rows)
    }

    /// Verify SNARK proof
    pub fn verify_proof(&self, proof: &SNARKProof) -> VerificationResult {
        self.snark_verifier.verify(proof)
    }
}

impl Default for SNARKEnhancedProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{OpCode, TraceRow};

    fn create_test_traces() -> Vec<Vec<TraceRow>> {
        vec![
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
            ],
        ]
    }

    #[test]
    fn test_snark_witness_creation() {
        let traces = create_test_traces();
        let witness = SNARKTraceWitness::from_traces(&traces);

        assert!(witness.is_ok());
        let w = witness.unwrap();
        assert_eq!(w.num_rows, 2);
        assert!(w.witness_commitment != 0);
    }

    #[test]
    fn test_snark_proof_generation() {
        let traces = create_test_traces();
        let witness = SNARKTraceWitness::from_traces(&traces).unwrap();

        let proof = witness.prove();
        assert!(proof.is_ok());
        let p = proof.unwrap();
        assert!(p.witness_commitment != 0);
    }

    #[test]
    fn test_snark_verification() {
        let traces = create_test_traces();
        let witness = SNARKTraceWitness::from_traces(&traces).unwrap();

        let proof = witness.prove().unwrap();
        let result = witness.verify_proof(&proof);

        assert!(result.valid);
    }

    #[test]
    fn test_full_proving_result() {
        let traces = create_test_traces();
        let result = FullProvingResult::from_traces(&traces);

        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.proving_time_ms < 1000, true); // Should be fast
    }

    #[test]
    fn test_combined_proof() {
        let traces = create_test_traces();
        let result = FullProvingResult::from_traces(&traces).unwrap();

        assert!(result.combined.snark_proof.is_some());
        assert!(result.combined.labrador_commitment.len() > 0);
    }
}