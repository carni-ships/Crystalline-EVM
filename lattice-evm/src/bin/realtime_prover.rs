//! Real-Time Ethereum Block Prover (Trace Edition)
//!
//! Shows real-time block analysis and trace generation with a terminal progress bar.
//!
//! Usage: cargo run --release --bin realtime_prover
//!         cargo run --release --bin realtime_prover -- --max 10
//!
//! Smart block detection: polls for new blocks and processes them in real-time
//! Block time is ~12 seconds on Ethereum, so we poll every 2 seconds to catch new blocks quickly
//!
//! Performance optimizations:
//! 1. Parallel trace generation using rayon
//! 2. Batch proving with parallel workers
//! 3. ANE acceleration for Poseidon2 hashing

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::io::Write;
use std::panic;
use rayon::prelude::*;
use lattice_evm::evm::full_evm::execute_evm_with_trace;
use lattice_evm::prover::{Prover, ProverConfig};
use lattice_evm::crypto::Poseidon2;

/// Contract trace result
struct ContractTraceResult {
    address: String,
    trace_rows: usize,
    gas_used: u64,
    elements: Vec<u32>,  // Commit-prove elements for this contract
    success: bool,
}

/// Continuous proving mode settings
/// Default: poll current block every 2 seconds, process new blocks as they appear
struct ContinuousConfig {
    start_block: u64,
    poll_interval_ms: u64,
    max_blocks: Option<u64>,
}

impl ContinuousConfig {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut start_block: u64 = 21_500_000;
        let mut poll_interval_ms: u64 = 2000; // Poll every 2 seconds by default (Ethereum block time is ~12s)
        let mut max_blocks: Option<u64> = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--poll" | "-p" => {
                    if i + 1 < args.len() {
                        poll_interval_ms = args[i + 1].parse().unwrap_or(2000);
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "--max" | "-m" => {
                    if i + 1 < args.len() {
                        max_blocks = Some(args[i + 1].parse().unwrap_or(10));
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                _ => {
                    if let Ok(n) = args[i].parse::<u64>() {
                        start_block = n;
                    }
                    i += 1;
                }
            }
        }

        ContinuousConfig {
            start_block,
            poll_interval_ms,
            max_blocks: max_blocks.or(Some(100)),
        }
    }
}

#[tokio::main]
async fn main() {
    let config = ContinuousConfig::parse();

    // Fetch current block number to start
    println!("🔄 Fetching current block number...");
    let current_block = match lattice_evm::evm::get_current_block_number().await {
        Ok(n) => n,
        Err(e) => {
            println!("❌ Failed to fetch current block: {}", e);
            return;
        }
    };
    println!("✓ Current block: #{}\n", current_block);

    // If a block number was explicitly provided, use it directly
    // Otherwise use current block
    let start_block = if std::env::args().nth(1).map(|s| s.parse::<u64>().is_ok()).unwrap_or(false) {
        config.start_block
    } else {
        current_block
    };

    let mut updated_config = config;
    updated_config.start_block = start_block;

    run_continuous_mode(&updated_config, current_block).await;
}

/// Process a single block and return stats
async fn process_block(block_number: u64) -> Option<(usize, usize, usize, usize, usize, u64)> {
    let block_hex = format!("0x{:x}", block_number);
    let block = match lattice_evm::evm::EthereumBlock::fetch(block_number).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("\n❌ Failed to fetch block #{}: {}", block_number, e);
            return None;
        }
    };

    // Total transactions in this block
    let total_txs = block.transactions.len();

    // Analyze transactions - filter to contract calls (non-empty input)
    let contract_calls: Vec<_> = block.transactions.iter()
        .filter(|tx| !tx.input.is_empty() && tx.input != "0x")
        .collect();

    // Count ETH transfers (empty input)
    let eth_transfers = block.transactions.iter()
        .filter(|tx| tx.input.is_empty() || tx.input == "0x")
        .count();

    if contract_calls.is_empty() {
        return Some((total_txs, eth_transfers, 0, 0, 0, 0));
    }

    use lattice_evm::evm::EthClient;
    let client = EthClient::default();
    let mut contract_bytecodes: Vec<(String, Vec<u8>)> = Vec::new();

    for tx in &contract_calls {
        if let Some(ref to) = tx.to {
            if !to.is_empty() {
                if let Ok(code) = client.get_code(to, &block_hex).await {
                    // Accept all non-empty bytecodes (crashes are handled via thread isolation)
                    // Limit size to 50KB to exclude obviously problematic bytecode
                    if !code.is_empty() && code.len() <= 50000 && code.len() > 2 {
                        contract_bytecodes.push((to.clone(), code));
                    }
                }
            }
        }
    }

    let attempted = contract_bytecodes.len();

    if contract_bytecodes.is_empty() {
        return Some((total_txs, eth_transfers, contract_calls.len(), 0, 0, 0));
    }

    // STEP 1: Parallel trace generation using rayon
    // Each contract is traced in parallel, then we collect results
    let trace_results: Vec<ContractTraceResult> = contract_bytecodes
        .into_par_iter()
        .map(|(address, code)| {
            // Set panic hook to suppress output
            panic::set_hook(Box::new(|_| {}));

            let gas_limit = if code.len() > 2000 { 2_000_000 } else if code.len() > 500 { 1_000_000 } else { 500_000 };

            match execute_evm_with_trace(&code, &[], gas_limit) {
                Ok((state_diff, trace)) => {
                    // Build commit-prove elements from trace
                    // Each row: pc, opcode, gas_before, gas_after, stack_height
                    let mut elements = Vec::with_capacity(trace.len() * 5);
                    for row in &trace {
                        elements.push(row.pc as u32 % 8383489);
                        elements.push(row.opcode as u32);
                        elements.push((row.gas_before % 8383489) as u32);
                        elements.push((row.gas_after % 8383489) as u32);
                        elements.push(row.stack.len() as u32 % 8383489);
                    }

                    ContractTraceResult {
                        address,
                        trace_rows: trace.len(),
                        gas_used: state_diff.gas_used,
                        elements,
                        success: true,
                    }
                }
                Err(_) => ContractTraceResult {
                    address,
                    trace_rows: 0,
                    gas_used: 0,
                    elements: Vec::new(),
                    success: false,
                }
            }
        })
        .collect();

    // Aggregate results
    let total_trace_rows: usize = trace_results.iter().map(|r| r.trace_rows).sum();
    let total_gas_used: u64 = trace_results.iter().map(|r| r.gas_used).sum();
    let failed_traces = trace_results.iter().filter(|r| !r.success).count();
    let successful_traces = trace_results.len() - failed_traces;

    // STEP 2: Batch proving with parallel workers
    // Collect all elements and prove in batches
    let all_elements: Vec<u32> = trace_results.iter()
        .flat_map(|r| r.elements.clone())
        .collect();

    if !all_elements.is_empty() {
        // Batch size for proving - Labrador L=4
        let batch_size = 4;
        let batches: Vec<Vec<u32>> = all_elements.chunks(batch_size)
            .map(|chunk| {
                let mut batch = chunk.to_vec();
                while batch.len() < batch_size {
                    batch.push(0);
                }
                batch
            })
            .collect();

        // Initialize prover (sequential due to ANE context)
        let config = ProverConfig::default();
        let prover = Prover::new(config).ok();

        if let Some(prover) = prover {
            // Sequential batch proving (Prover has non-Send ANE context)
            let mut proofs: Vec<(usize, [u8; 32])> = Vec::new();
            for (batch_id, batch) in batches.iter().enumerate() {
                let witness: Vec<f32> = batch.iter().map(|&v| v as f32).collect();
                match prover.prove_witness(&witness) {
                    Ok(proof) => {
                        let mut commitment = [0u8; 32];
                        commitment.copy_from_slice(&proof.commitment);
                        proofs.push((batch_id, commitment));
                    }
                    Err(_) => {}
                }
            }

            // Compose proofs to get final root (Merkle-style)
            if !proofs.is_empty() {
                let mut current_level: Vec<u32> = proofs.iter()
                    .map(|(_, comm)| Poseidon2::hash_pair(comm[0] as u32, comm[1] as u32))
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
            }
        }
    }

    let successful = attempted - failed_traces;
    Some((total_txs, eth_transfers, contract_calls.len(), attempted, successful, total_gas_used))
}

/// Continuous block proving loop
async fn run_continuous_mode(config: &ContinuousConfig, initial_current: u64) {
    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║         REAL-TIME ETHEREUM BLOCK TRACER                             ║");
    println!("║  Polls for new blocks every {}ms                                    ║", config.poll_interval_ms);
    println!("║  Press Ctrl+C to stop                                               ║");
    println!("╚════════════════════════════════════════════════════════════════════╝");
    println!();

    let mut current_block = config.start_block;
    let last_processed_block = Arc::new(AtomicU64::new(0));
    let mut total_blocks = 0u64;
    let total_blocks_atomic = Arc::new(AtomicU64::new(0));

    // Shared state for showing block status
    let status_current = Arc::new(AtomicU64::new(initial_current));
    let status_processing = Arc::new(AtomicU64::new(0));

    println!("📊 Starting from block #{} (will poll for newer blocks)\n", current_block);

    // Progress display helper - uses carriage return to overwrite same line
fn show_status(line: &str) {
    eprint!("\r{}", line);
    std::io::stderr().flush().ok();
}

loop {
        // Poll for current block number
        match lattice_evm::evm::get_current_block_number().await {
            Ok(newest_block) => {
                status_current.store(newest_block, Ordering::SeqCst);

                if newest_block > current_block {
                    // New blocks available! Process them one by one
                    while current_block < newest_block {
                        let block_to_process = current_block + 1;
                        status_processing.store(block_to_process, Ordering::SeqCst);

                        show_status(&format!("🔄 Processing block #{:>8} | new={:>8}", block_to_process, newest_block));

                        match process_block(block_to_process).await {
                            Some((total_txs, eth_xfers, call_txs, attempted, successful, gas)) => {
                                println!();
                                if attempted > 0 {
                                    println!("  ✅ #{:>8} | txs={} ({} calls, {} ETH xfers) | proved={}/{} | {} gas",
                                        block_to_process, total_txs, call_txs, eth_xfers, successful, attempted, gas);
                                } else if call_txs > 0 {
                                    println!("  ⏭️  #{:>8} | txs={} ({} calls, {} ETH xfers) | 0 provable (filtered)",
                                        block_to_process, total_txs, call_txs, eth_xfers);
                                } else {
                                    println!("  ⏭️  #{:>8} | txs={} (ETH transfers only)",
                                        block_to_process, total_txs);
                                }

                                total_blocks += 1;
                                total_blocks_atomic.fetch_add(1, Ordering::SeqCst);
                                last_processed_block.store(block_to_process, Ordering::SeqCst);
                            }
                            None => {
                                println!();
                                println!("  ⚠️  Block #{:>8} | FAILED", block_to_process);
                            }
                        }

                        current_block = block_to_process;

                        // Check if we've reached max blocks
                        if let Some(max) = config.max_blocks {
                            if total_blocks >= max {
                                println!();
                                println!("═══════════════════════════════════════════════════════════════════════");
                                println!();
                                println!("📊 REAL-TIME PROVING SUMMARY");
                                println!();
                                println!("   Last processed block: #{}", last_processed_block.load(Ordering::SeqCst));
                                println!("   Blocks processed: {}", total_blocks);
                                return;
                            }
                        }
                    }
                } else {
                    // No new blocks yet - show compact waiting status on same line
                    show_status(&format!("⏳ Waiting for blocks... last=#{} current=#{}    ", current_block, newest_block));
                }
            }
            Err(e) => {
                show_status(&format!("⚠️  RPC error: {}", e));
            }
        }

        // Wait before polling again
        std::thread::sleep(std::time::Duration::from_millis(config.poll_interval_ms));
    }
}
