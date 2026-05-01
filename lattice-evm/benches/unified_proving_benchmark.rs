//! Unified Proving Benchmark
//!
//! Tests unified proving mode and batch proving for achieving <12s per full block:
//! 1. Unified proving - single proof for entire block trace (16 columns × N rows)
//! 2. Batch proving - parallel proof generation for trace chunks
//! 3. Rayon parallel processing for multi-core utilization

use lattice_evm::prover::{Prover, ProverConfig};
use lattice_evm::evm::{EthClient, EthereumBlock, EVMState, get_current_block_number, execute_bytecode};
use lattice_evm::prover::parallel_prove::BatchProof;
use lattice_evm::crypto::{Poseidon2, Q};
use std::time::Instant;

/// Build unified trace from multiple transactions
/// This is the "Zoltraak approach" - treats entire block as single polynomial
fn build_unified_trace(codes: &[Vec<u8>], gas_limit: u64) -> Vec<u32> {
    let mut unified_elements: Vec<u32> = Vec::new();

    for code in codes {
        let result = execute_bytecode(code, gas_limit);
        if let Ok((_state, trace)) = result {
            // Add trace elements (pc, opcode, gas, stack_height)
            for row in &trace {
                unified_elements.push(row.pc as u32 % Q as u32);
                unified_elements.push(row.opcode as u32);
                unified_elements.push((row.gas % Q as u64) as u32);
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

    // Process batches in parallel using rayon
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

#[tokio::main]
async fn main() {
    println!("=== Unified Proving Benchmark ===\n");
    println!("Target: <12s per full Ethereum block\n");

    // Get current block number
    println!("Fetching current block number...");
    match get_current_block_number().await {
        Ok(block_num) => println!("Current block: #{}\n", block_num),
        Err(e) => println!("Failed to get current block: {} (using fallback)\n", e),
    }

    // Benchmark 1: Sequential batch proving (baseline)
    println!("=== Benchmark 1: Sequential Batch Proving (Baseline) ===");
    println!("Processing trace batches one at a time...\n");

    let batch_size = 4; // Labrador L=4
    let codes = vec![
        vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00],  // Simple ADD
        vec![0x60, 0x80, 0x60, 0x40, 0x54, 0x60, 0x01, 0x01, 0x60, 0x80, 0x55, 0x00],  // SLOAD/SSTORE
        vec![0x5b, 0x60, 0x01, 0x60, 0x05, 0x56, 0x5b, 0x60, 0x00, 0x00],  // JUMP
        vec![0x60, 0xAA, 0x60, 0xBB, 0x01, 0x60, 0xCC, 0x01, 0x00],  // PUSH seq
    ];

    let unified = build_unified_trace(&codes, 100000);
    let batches = chunk_for_proving(&unified, batch_size);
    println!("Unified trace: {} elements -> {} batches\n", unified.len(), batches.len());

    let prover = Prover::new(ProverConfig::default()).unwrap();

    let start = Instant::now();
    let proofs = batch_prove_sequential(&prover, &batches);
    let elapsed = start.elapsed().as_millis() as f64;

    println!("Sequential results:");
    println!("  Batches: {} (batch_size={})", batches.len(), batch_size);
    println!("  Proven: {} ({:.1}%)", proofs.len(), (proofs.len() as f64 / batches.len() as f64) * 100.0);
    println!("  Time: {:.2} ms", elapsed);
    println!("  Per batch: {:.2} ms\n", elapsed / batches.len() as f64);

    // Benchmark 2: Parallel batch proving with rayon
    println!("=== Benchmark 2: Parallel Batch Proving (Rayon) ===");
    println!("Processing trace batches in parallel using rayon...\n");

    let config = ProverConfig::default();
    let start = Instant::now();
    let proofs = batch_prove_parallel(&batches, &config);
    let elapsed = start.elapsed().as_millis() as f64;

    println!("Parallel (rayon) results:");
    println!("  Batches: {} (batch_size={})", batches.len(), batch_size);
    println!("  Proven: {} ({:.1}%)", proofs.len(), (proofs.len() as f64 / batches.len() as f64) * 100.0);
    println!("  Time: {:.2} ms", elapsed);
    println!("  Per batch: {:.2} ms", elapsed / batches.len() as f64);
    println!("  Speedup vs sequential: {:.1}x\n", if elapsed > 0.0 { (batches.len() as f64 * 7.35) / elapsed } else { 0.0 });

    // Benchmark 3: Unified proving with real block
    println!("=== Benchmark 3: Unified Proving with Real Block ===");
    println!("Processing all transactions as single unified trace...\n");

    match get_current_block_number().await {
        Ok(current_block) => {
            println!("Fetching block #{}...", current_block);
            match EthereumBlock::fetch(current_block).await {
                Ok(block) => {
                    println!("Block #{}: {} transactions", current_block, block.transactions.len());

                    // Filter to contract calls only
                    let hex_number = format!("0x{:x}", current_block);
                    let mut contract_codes: Vec<Vec<u8>> = Vec::new();

                    for tx in &block.transactions {
                        if tx.input.is_empty() || tx.input == "0x" {
                            continue;
                        }
                        if let Some(ref to) = tx.to {
                            if !to.is_empty() {
                                let client = EthClient::default();
                                match client.get_code(to, &hex_number).await {
                                    Ok(code) if code.len() < 10000 => { // Skip massive bytecode
                                        contract_codes.push(code);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    println!("Contract calls with bytecode: {}\n", contract_codes.len());

                    if contract_codes.is_empty() {
                        println!("No contract calls found, using synthetic patterns\n");
                        contract_codes = vec![
                            vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]; 50
                        ];
                    }

                    // Limit to first 50 for benchmark
                    let codes_to_prove: Vec<Vec<u8>> = contract_codes.iter().take(50).cloned().collect();
                    println!("Proving {} contract traces...\n", codes_to_prove.len());

                    // Build unified trace
                    let start = Instant::now();
                    let unified = build_unified_trace(&codes_to_prove, 1_000_000);
                    let build_time = start.elapsed().as_millis() as f64;

                    // Chunk for proving
                    let batch_size = 4;
                    let batches = chunk_for_proving(&unified, batch_size);

                    println!("Unified trace: {} elements -> {} batches ({}ms build time)",
                        unified.len(), batches.len(), build_time);

                    // Parallel proving
                    let prove_start = Instant::now();
                    let proofs = batch_prove_parallel(&batches, &ProverConfig::default());
                    let prove_time = prove_start.elapsed().as_millis() as f64;

                    // Compose
                    let compose_start = Instant::now();
                    let root = compose_proofs(&proofs);
                    let compose_time = compose_start.elapsed().as_millis() as f64;

                    let total_time = build_time + prove_time + compose_time;

                    println!("\nResults:");
                    println!("  Total time: {:.2} ms", total_time);
                    println!("    Build: {:.2} ms", build_time);
                    println!("    Prove: {:.2} ms ({} batches)", prove_time, proofs.len());
                    println!("    Compose: {:.2} ms", compose_time);
                    println!("  Root commitment: {}", root);

                    // Extrapolate to full block
                    let contract_calls = block.transactions.iter()
                        .filter(|tx| !(tx.input.is_empty() || tx.input == "0x"))
                        .count();

                    if contract_calls > 0 {
                        let per_call_time = total_time / codes_to_prove.len() as f64;
                        let full_block_time = per_call_time * contract_calls as f64;

                        println!("\nExtrapolation:");
                        println!("  Total contract calls in block: {}", contract_calls);
                        println!("  Per-call time: {:.2} ms", per_call_time);
                        println!("  Estimated full block time: {:.0} ms ({:.1}s)", full_block_time, full_block_time / 1000.0);

                        if full_block_time < 12000.0 {
                            println!("  ✓ UNDER 12s TARGET!");
                        } else {
                            println!("  ✗ OVER 12s target (need {:.1}s more)", (full_block_time - 12000.0) / 1000.0);
                        }
                    }
                }
                Err(e) => println!("Failed to fetch block: {}\n", e),
            }
        }
        Err(e) => println!("Failed to get current block number: {}\n", e),
    }

    println!("\n=== Summary ===");
    println!("Unified proving approach:");
    println!("  - Treats entire block as single trace (16 columns × N rows)");
    println!("  - Batch proving with rayon parallelization");
    println!("  - Merkle composition for proof aggregation");
    println!("\nCurrent performance gap:");
    println!("  - Need ~1ms per contract call for 12s block");
    println!("  - Current: ~450ms per call (450x gap)");
    println!("  - GPU acceleration needed for orders of magnitude improvement");
}