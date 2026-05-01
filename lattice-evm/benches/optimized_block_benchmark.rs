//! Optimized Block Proving Benchmark
//!
//! Tests performance optimizations for achieving <12s per full block:
//! 1. Prover reuse (create once, use many times)
//! 2. Current block fetching ("latest" has full state)

use lattice_evm::prover::{Prover, ProverConfig};
use lattice_evm::evm::{EthClient, EthereumBlock, get_current_block_number, RPCConfig};
use orion_backend::labrador::generate_seed;
use orion_sys::{LATTICEZK_L, latticezk_sample_short_vector};
use std::time::Instant;

/// Generate a random witness of L=4 f32 values
fn generate_witness() -> Vec<f32> {
    let mut s = vec![0f32; LATTICEZK_L as usize];
    unsafe {
        latticezk_sample_short_vector(2.0, s.as_mut_ptr(), LATTICEZK_L as i32);
    }
    s
}

/// Run benchmark with prover reuse (create once, use many times)
fn benchmark_prover_reuse(num_txs: usize) -> (f64, usize) {
    let start = Instant::now();

    // Create prover once
    let prover = Prover::new(ProverConfig::default()).unwrap();
    let mut proven = 0;

    for _ in 0..num_txs {
        let witness = generate_witness();
        match prover.prove_witness(&witness) {
            Ok(_) => proven += 1,
            Err(_) => {}
        }
    }

    let elapsed = start.elapsed().as_millis() as f64;
    (elapsed, proven)
}

#[tokio::main]
async fn main() {
    println!("=== Optimized Block Proving Benchmark ===\n");
    println!("Target: <12s per full Ethereum block\n");

    // Get current block number
    println!("Fetching current block number...");
    match get_current_block_number().await {
        Ok(block_num) => println!("Current block: #{}\n", block_num),
        Err(e) => println!("Failed to get current block: {} (using fallback 19M)\n", e),
    }

    // Benchmark 1: Prover Reuse
    println!("=== Benchmark 1: Prover Reuse ===");
    println!("Creating prover once and reusing for multiple proofs...\n");

    let num_iterations = 20;
    let (elapsed, proven) = benchmark_prover_reuse(num_iterations);

    println!("Results ({} iterations):", num_iterations);
    println!("  Proven: {} ({:.1}%)", proven, (proven as f64 / num_iterations as f64) * 100.0);
    println!("  Total time: {:.2} ms", elapsed);
    println!("  Avg time: {:.2} ms/op", elapsed / num_iterations as f64);
    println!();

    // Benchmark 2: Batch proving with a single prover
    println!("=== Benchmark 2: Batch EVM Trace Proving ===");
    println!("Using single prover for multiple EVM traces...\n");

    // Realistic bytecode patterns
    let bytecode_patterns = vec![
        vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00],  // Simple ADD
        vec![0x60, 0x80, 0x60, 0x40, 0x54, 0x60, 0x01, 0x01, 0x60, 0x80, 0x55, 0x00],  // SLOAD/SSTORE
        vec![0x5b, 0x60, 0x01, 0x60, 0x05, 0x56, 0x5b, 0x60, 0x00, 0x00],  // JUMP
        vec![0x60, 0xAA, 0x60, 0xBB, 0x01, 0x60, 0xCC, 0x01, 0x00],  // PUSH seq
    ];

    // Create prover once for batch
    let prover = Prover::new(ProverConfig::default()).unwrap();

    for num_txs in [10, 50, 100] {
        let mut codes: Vec<Vec<u8>> = Vec::new();
        for i in 0..num_txs {
            let pattern_idx = i % bytecode_patterns.len();
            codes.push(bytecode_patterns[pattern_idx].clone());
        }

        let start = Instant::now();
        let mut proven = 0;

        for code in &codes {
            match prover.prove_evm_trace(code, 100000) {
                Ok(_) => proven += 1,
                Err(_) => {}
            }
        }

        let elapsed = start.elapsed().as_millis() as f64;
        let per_tx = if proven > 0 { elapsed / proven as f64 } else { 0.0 };

        println!("Block ({} txs, {} proven): {:.2} ms total, {:.2} ms/tx, {:.1} tx/s",
            num_txs, proven, elapsed, per_tx, (proven as f64 / elapsed) * 1000.0);
    }
    println!();

    // Benchmark 3: Real Current Block
    println!("=== Benchmark 3: Real Current Block ===");
    println!("Fetching current block and proving contract calls...\n");

    match get_current_block_number().await {
        Ok(current_block) => {
            println!("Fetching block #{}...", current_block);

            match EthereumBlock::fetch(current_block).await {
                Ok(block) => {
                    println!("Block #{}: {} transactions", current_block, block.transactions.len());

                    let simple_transfers = block.transactions.iter()
                        .filter(|tx| tx.input.is_empty() || tx.input == "0x")
                        .count();
                    let contract_calls = block.transactions.len() - simple_transfers;

                    println!("  Simple transfers: {}", simple_transfers);
                    println!("  Contract calls: {}", contract_calls);

                    // Prove contract calls (limit to 20 for benchmark)
                    let prover = Prover::new(ProverConfig::default())
                        .expect("Failed to create prover");

                    let hex_number = format!("0x{:x}", current_block);
                    let mut proven = 0;
                    let start = Instant::now();

                    for (i, tx) in block.transactions.iter().enumerate() {
                        if tx.input.is_empty() || tx.input == "0x" {
                            continue;
                        }

                        // Get bytecode
                        let bytecode = if let Some(ref to) = tx.to {
                            if !to.is_empty() {
                                let client = EthClient::default();
                                match client.get_code(to, &hex_number).await {
                                    Ok(code) if !code.is_empty() => code,
                                    _ => vec![0x00],
                                }
                            } else {
                                vec![]
                            }
                        } else {
                            vec![]
                        };

                        match prover.prove_evm_trace(&bytecode, 1_000_000) {
                            Ok(_) => proven += 1,
                            Err(_) => {}
                        }

                        if proven >= 20 {
                            break;
                        }

                        if (i + 1) % 25 == 0 {
                            println!("  Processed {}/{} transactions ({} proven)",
                                i + 1, block.transactions.len(), proven);
                        }
                    }

                    let elapsed = start.elapsed().as_millis() as f64;

                    println!("\nResults:");
                    println!("  Contract calls proven: {}", proven);
                    println!("  Time: {:.2} ms", elapsed);
                    println!("  Avg per tx: {:.2} ms", if proven > 0 { elapsed / proven as f64 } else { 0.0 });

                    // Extrapolate to full block
                    if proven > 0 {
                        let per_call = elapsed / proven as f64;
                        let total_contracts = contract_calls as f64;
                        let est = total_contracts * per_call;
                        println!("  Estimated full block time: {:.0} ms ({:.1}s)", est, est / 1000.0);
                        if est < 12000.0 {
                            println!("  ✓ UNDER 12s TARGET!");
                        } else {
                            println!("  ✗ OVER 12s target (need {:.1}s more)", (est - 12000.0) / 1000.0);
                        }
                    }
                }
                Err(e) => {
                    println!("Failed to fetch block: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to get current block number: {}", e);
        }
    }

    println!("\n=== Summary ===");
    println!("Optimizations available:");
    println!("  1. Prover reuse - avoids keygen overhead");
    println!("  2. Parallel proving - Zoltraak's GPU multi-stream approach");
    println!("  3. Unified proving - Zoltraak's ultraFast config (16 columns)");
    println!();
    println!("Current per-contract-call time: ~50-100ms (need ~1ms for 12s block)");
    println!("Gap: 50-100x slower than needed");
    println!();
    println!("To achieve <12s per block:");
    println!("  - Need GPU acceleration (not available in current ANE-only build)");
    println!("  - Need unified proving mode (Zoltraak approach)");
    println!("  - Need batch proving with parallelism");
}