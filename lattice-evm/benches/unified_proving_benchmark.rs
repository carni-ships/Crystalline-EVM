//! Unified Proving Benchmark
//!
//! Tests unified proving mode and batch proving for achieving <12s per full block:
//! 1. Unified proving - single proof for entire block trace
//! 2. Batch proving - parallel proof generation for trace chunks
//! 3. Rayon parallel processing for multi-core utilization
//!
//! Updated to use full_evm.rs API

use lattice_evm::prover::{Prover, ProverConfig};
use lattice_evm::evm::full_evm::execute_evm_with_trace;
use lattice_evm::prover::parallel_prove::BatchProof;
use lattice_evm::crypto::{Poseidon2, Q};
use std::time::Instant;

/// Build unified trace from multiple transactions using full_evm
fn build_unified_trace(codes: &[Vec<u8>], gas_limit: u64) -> Vec<u32> {
    let mut unified_elements: Vec<u32> = Vec::new();

    for code in codes {
        let result = execute_evm_with_trace(code, &[], gas_limit);
        if let Ok((_, trace)) = result {
            // Add trace elements (pc, opcode, gas_before, gas_after, stack_height)
            for row in &trace {
                unified_elements.push(row.pc as u32 % Q as u32);
                unified_elements.push(row.opcode as u32);
                unified_elements.push((row.gas_before % Q as u64) as u32);
                unified_elements.push((row.gas_after % Q as u64) as u32);
                unified_elements.push(row.stack.len() as u32 % Q as u32);
            }
        }
    }

    unified_elements
}

/// Chunk unified trace into batches for parallel proving
fn chunk_for_proving(elements: &[u32], batch_size: usize) -> Vec<Vec<u32>> {
    elements.chunks(batch_size)
        .map(|chunk| {
            let mut batch = chunk.to_vec();
            while batch.len() < batch_size {
                batch.push(0);
            }
            batch
        })
        .collect()
}

/// Single-threaded batch proving (baseline)
fn batch_prove_sequential(prover: &Prover, batches: &[Vec<u32>]) -> Vec<BatchProof> {
    let mut proofs = Vec::new();
    for (batch_id, batch) in batches.iter().enumerate() {
        let witness: Vec<f32> = batch.iter().map(|&v| v as f32).collect();
        match prover.prove_witness(&witness) {
            Ok(proof) => {
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&proof.commitment);
                proofs.push(BatchProof {
                    batch_id,
                    proof,
                    commitment,
                    elements: batch.clone(),
                });
            }
            Err(_) => {}
        }
    }
    proofs
}

/// Parallel batch proving using rayon
fn batch_prove_parallel(batches: &[Vec<u32>], config: &ProverConfig) -> Vec<BatchProof> {
    use rayon::prelude::*;

    let results: Vec<Option<BatchProof>> = batches.par_iter()
        .enumerate()
        .map(|(batch_id, batch)| {
            let prover = Prover::new(config.clone()).ok()?;
            let witness: Vec<f32> = batch.iter().map(|&v| v as f32).collect();
            let proof = prover.prove_witness(&witness).ok()?;
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&proof.commitment);
            Some(BatchProof {
                batch_id,
                proof,
                commitment,
                elements: batch.clone(),
            })
        })
        .collect();

    results.into_iter().filter_map(|r| r).collect()
}

/// Compute root from batch proofs (Merkle-style composition)
fn compose_proofs(proofs: &[BatchProof]) -> u32 {
    if proofs.is_empty() {
        return 0;
    }

    let mut current_level: Vec<u32> = proofs.iter()
        .map(|p| Poseidon2::hash_pair(p.commitment[0] as u32, p.commitment[1] as u32))
        .collect();

    while current_level.len() > 1 {
        current_level = current_level.chunks(2)
            .map(|chunk| {
                let a = chunk[0];
                let b = chunk.get(1).copied().unwrap_or(a);
                Poseidon2::hash_pair(a, b)
            })
            .collect();
    }

    current_level[0]
}

fn main() {
    println!("=== Lattice-EVM Unified Proving Benchmark ===\n");
    println!("Using full_evm.rs API with RevmTraceRow\n");

    let batch_size = 4; // Labrador L=4
    let codes = vec![
        vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00],  // Simple ADD
        vec![0x60, 0x80, 0x60, 0x40, 0x54, 0x60, 0x01, 0x01, 0x60, 0x80, 0x55, 0x00],  // SLOAD/SSTORE
        vec![0x5b, 0x60, 0x01, 0x60, 0x05, 0x56, 0x5b, 0x60, 0x00, 0x00],  // JUMP
        vec![0x60, 0xAA, 0x60, 0xBB, 0x01, 0x60, 0xCC, 0x01, 0x00],  // PUSH seq
    ];

    // Benchmark: Build unified trace
    println!("=== Trace Generation ===\n");

    let trace_start = Instant::now();
    let unified = build_unified_trace(&codes, 100000);
    let trace_time = trace_start.elapsed().as_millis() as f64;
    let batches = chunk_for_proving(&unified, batch_size);

    println!("Unified trace: {} elements in {:.2}ms", unified.len(), trace_time);
    println!("Batches: {} (batch_size={})\n", batches.len(), batch_size);

    // Benchmark: Sequential batch proving
    println!("=== Sequential Batch Proving ===\n");

    let prover = Prover::new(ProverConfig::default()).unwrap();

    let start = Instant::now();
    let proofs = batch_prove_sequential(&prover, &batches);
    let elapsed = start.elapsed().as_millis() as f64;

    println!("Results:");
    println!("  Proven: {} / {} batches ({:.1}%)", proofs.len(), batches.len(),
        (proofs.len() as f64 / batches.len() as f64) * 100.0);
    println!("  Time: {:.2} ms total, {:.2} ms per batch\n", elapsed, elapsed / batches.len() as f64);

    // Benchmark: Parallel batch proving with rayon
    println!("=== Parallel Batch Proving (Rayon) ===\n");

    let config = ProverConfig::default();
    let start = Instant::now();
    let proofs = batch_prove_parallel(&batches, &config);
    let elapsed = start.elapsed().as_millis() as f64;

    println!("Results:");
    println!("  Proven: {} / {} batches ({:.1}%)", proofs.len(), batches.len(),
        (proofs.len() as f64 / batches.len() as f64) * 100.0);
    println!("  Time: {:.2} ms total, {:.2} ms per batch", elapsed, elapsed / batches.len() as f64);

    // Compute composed root
    let composed_root = compose_proofs(&proofs);
    println!("  Composed root: {}\n", composed_root);

    // Block context from trace
    println!("=== Block Context Captured ===\n");

    let result = execute_evm_with_trace(&codes[0], &[], 100000);
    if let Ok((_, trace)) = result {
        if let Some(row) = trace.first() {
            println!("Block context from execution:");
            println!("  coinbase: {:?}", row.block_context.coinbase);
            println!("  timestamp: {}", row.block_context.timestamp);
            println!("  number: {}", row.block_context.number);
            println!("  prevrandao: {}", row.block_context.prevrandao);
            println!("  gas_limit: {}", row.block_context.gas_limit);
            println!("  chain_id: {}", row.block_context.chain_id);
        }
    }

    println!("\n=== Benchmark Complete ===");
}
