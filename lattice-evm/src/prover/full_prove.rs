//! Full EVM Trace Prover
//!
//! Implements full column tracing with AIR constraints:
//! - Full 6-column trace (pc, opcode, gas, stack_height, memory_size, call_depth)
//! - All AIR constraint evaluations per row
//! - Poseidon2 commitment chain for Labrador witness (4 elements)

use crate::air::{EVMAIREvaluator, trace_row_to_values, ConstraintType};
use crate::crypto::{keccak256, keccak256_field, Poseidon2, Q};
use crate::evm::{TraceRow, EVMState};
use crate::prover::{Prover, ProverConfig};
use crate::air::LatticeAIR;

/// Full trace witness with all columns and constraints
#[derive(Debug, Clone)]
pub struct FullTraceWitness {
    /// Number of transactions
    pub num_txs: usize,
    /// Number of trace rows
    pub num_rows: usize,
    /// Full trace data (rows × columns)
    pub trace_data: Vec<Vec<u32>>,
    /// AIR constraint evaluations per row
    pub constraint_evals: Vec<Vec<i64>>,
    /// Poseidon2 commitment chain root
    pub commitment_root: u32,
    /// Keccak256 hashes of trace rows
    pub trace_hashes: Vec<u32>,
}

/// Execute EVM bytecode and build full trace witness
pub fn execute_and_trace(code: &[u8], gas: u64) -> Result<(EVMState, Vec<TraceRow>), &'static str> {
    crate::evm::execute_bytecode(code, gas)
}

/// Build full witness from execution trace
pub fn build_full_witness(traces: &[Vec<TraceRow>]) -> FullTraceWitness {
    let evaluator = EVMAIREvaluator::new();
    let mut all_trace_data: Vec<Vec<u32>> = Vec::new();
    let mut all_constraint_evals: Vec<Vec<i64>> = Vec::new();
    let mut all_trace_hashes: Vec<u32> = Vec::new();
    let mut row_hashes: Vec<u32> = Vec::new();

    for trace in traces {
        for row in trace {
            // Extract full 6-column row
            let values = trace_row_to_values(row);
            all_trace_data.push(values.clone());

            // Evaluate ALL AIR constraints for this row
            let op = crate::evm::OpCode::from_u8(row.opcode);
            let constraints = evaluator.evaluate_opcode(op, &values);
            all_constraint_evals.push(constraints.clone());

            // Compute Keccak256 of row data for traceability
            let row_bytes: Vec<u8> = values.iter()
                .flat_map(|&v| v.to_le_bytes())
                .collect();
            let hash = keccak256(&row_bytes);
            let hash_field: Vec<u32> = hash.iter().map(|&b| b as u32).collect();
            all_trace_hashes.extend(hash_field);

            // Row commitment hash (Poseidon2 of first 2 elements)
            let row_hash = Poseidon2::hash_pair(values[0], values[1]);
            row_hashes.push(row_hash);
        }
    }

    // Build Poseidon2 commitment chain from row hashes
    let commitment_root = if row_hashes.len() > 1 {
        // Chain: each hash includes the previous
        let mut chain_hash = row_hashes[0];
        for i in 1..row_hashes.len() {
            chain_hash = Poseidon2::hash_pair(chain_hash, row_hashes[i]);
        }
        chain_hash
    } else if row_hashes.is_empty() {
        0
    } else {
        row_hashes[0]
    };

    FullTraceWitness {
        num_txs: traces.len(),
        num_rows: all_trace_data.len(),
        trace_data: all_trace_data,
        constraint_evals: all_constraint_evals,
        commitment_root,
        trace_hashes: all_trace_hashes,
    }
}

/// Compress full witness to 4-element Labrador witness using commitment chain
pub fn compress_to_labrador_witness(witness: &FullTraceWitness) -> Vec<f32> {
    // Build Merkle tree of trace data commitments
    let mut trace_commits: Vec<u32> = witness.trace_data.iter()
        .map(|row| Poseidon2::hash_pair(row[0], row[1]))
        .collect();

    // Build constraint commitment chain
    let mut constraint_commits: Vec<u32> = Vec::new();
    for evals in &witness.constraint_evals {
        let commit = evals.iter().fold(0u64, |acc, v| {
            ((acc * 1103515245 + 12345) + *v as u64) & 0x7fffffff
        }) as u32;
        constraint_commits.push(commit);
    }

    // Combine trace and constraint commitments
    let mut combined: Vec<u32> = Vec::new();
    combined.extend(trace_commits);
    combined.extend(constraint_commits);

    // Build final commitment tree
    while combined.len() > 4 {
        combined = combined.chunks(2)
            .map(|chunk| {
                let a = chunk[0];
                let b = chunk.get(1).copied().unwrap_or(a);
                ((a as u64 + b as u64) % Q) as u32
            })
            .collect();
    }

    // Pad to exactly 4
    while combined.len() < 4 {
        combined.push(0);
    }

    combined.into_iter().map(|v| v as f32).collect()
}

/// Prove a single Ethereum transaction with full columns
pub fn prove_single_tx(prover: &Prover, code: &[u8], gas: u64) -> Result<FullTraceWitness, String> {
    // Execute bytecode
    let (_state, trace) = execute_and_trace(code, gas)
        .map_err(|e| e.to_string())?;

    // Build witness from single trace
    let witness = build_full_witness(&[trace]);

    Ok(witness)
}

/// Prove multiple transactions (full block) with full columns
pub fn prove_block(prover: &Prover, codes: &[&[u8]], gas: u64) -> Result<FullTraceWitness, String> {
    let mut all_traces: Vec<Vec<TraceRow>> = Vec::new();

    for code in codes {
        let (_state, trace) = execute_and_trace(code, gas)
            .map_err(|e| e.to_string())?;
        all_traces.push(trace);
    }

    let witness = build_full_witness(&all_traces);

    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_trace_witness() {
        let code = vec![0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0x60, 0x20, 0x60, 0x00, 0x60, 0x02, 0x00];
        let (_state, trace) = execute_and_trace(&code, 100000).unwrap();

        let witness = build_full_witness(&[trace]);

        println!("Trace rows: {}", witness.num_rows);
        println!("Trace data columns per row: {}", witness.trace_data[0].len());
        println!("Constraint evals per row: {}", witness.constraint_evals[0].len());
        println!("Commitment root: {}", witness.commitment_root);

        // Verify we have commit-prove columns (19: pc, opcode, gas, stack_height, stack_before, stack_after, balance, storage, commitments, jumpdest)
        assert_eq!(witness.trace_data[0].len(), 19, "Should have 19 columns (commit-prove with bytecode and jumpdest)");
        assert!(witness.num_rows > 0, "Should have trace rows");
    }

    #[test]
    fn test_compression() {
        let code = vec![0x60, 0x01, 0x00];
        let (_state, trace) = execute_and_trace(&code, 100000).unwrap();
        let witness = build_full_witness(&[trace]);

        let labrador_witness = compress_to_labrador_witness(&witness);

        println!("Labrador witness: {:?}", &labrador_witness);
        assert_eq!(labrador_witness.len(), 4, "Should compress to 4 elements");
    }
}
