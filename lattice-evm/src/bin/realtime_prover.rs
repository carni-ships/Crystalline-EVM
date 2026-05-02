//! Real-Time Ethereum Block Prover (Trace Edition)
//!
//! Shows real-time block analysis and trace generation with a terminal progress bar.
//!
//! Usage: cargo run --bin realtime_prover
//!         cargo run --bin realtime_prover --max 10
//!
//! Smart block detection: polls for new blocks and processes them in real-time
//! Block time is ~12 seconds on Ethereum, so we poll every 2 seconds to catch new blocks quickly

use std::time::Instant;
use std::cmp::min;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use lattice_evm::evm::full_evm::execute_evm_with_trace;

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
        let mut set_explicitly = false;

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
                        set_explicitly = true;
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

/// Progress bar for terminal display
struct ProgressBar {
    total: usize,
    current: Arc<AtomicUsize>,
    width: usize,
    start_time: Instant,
}

impl ProgressBar {
    fn new(total: usize, width: usize) -> Self {
        ProgressBar {
            total,
            current: Arc::new(AtomicUsize::new(0)),
            width,
            start_time: Instant::now(),
        }
    }

    fn update(&self, current: usize) {
        self.current.store(min(current, self.total), Ordering::SeqCst);
    }

    fn get_current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    fn draw(&self, message: &str) {
        let current = self.get_current();
        let elapsed = self.start_time.elapsed();
        let elapsed_str = format_elapsed(elapsed);

        if self.total == 0 {
            let bar = "-".repeat(self.width);
            println!("\r[{}] {} (took {})", bar, message, elapsed_str);
            return;
        }

        let progress = current as f64 / self.total as f64;
        let filled = (progress * self.width as f64) as usize;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(self.width.saturating_sub(filled)));

        let percent = (progress * 100.0) as u32;
        print!(
            "\r[{}] {} {:>3}% ({}/{}) (took {})",
            bar, message, percent, current, self.total, elapsed_str
        );
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    fn finish(&self, message: &str) {
        let elapsed = self.start_time.elapsed();
        let elapsed_str = format_elapsed(elapsed);
        let bar = "█".repeat(self.width);
        println!("\r[{}] {} (took {})", bar, message, elapsed_str);
    }
}

fn format_elapsed(duration: std::time::Duration) -> String {
    let ms = duration.as_millis() as u64;
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        let seconds = ms / 1000;
        let ms_rem = ms % 1000;
        format!("{}.{:>03}s", seconds, ms_rem)
    }
}

fn short_addr(addr: &str) -> String {
    if addr.len() > 10 {
        format!("{}...", &addr[..10])
    } else {
        addr.to_string()
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
async fn process_block(block_number: u64) -> Option<(usize, usize, usize, u64)> {
    let block_hex = format!("0x{:x}", block_number);
    let block = match lattice_evm::evm::EthereumBlock::fetch(block_number).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("\n❌ Failed to fetch block #{}: {}", block_number, e);
            return None;
        }
    };

    // Analyze transactions
    let contract_calls: Vec<_> = block.transactions.iter()
        .filter(|tx| !tx.input.is_empty() && tx.input != "0x")
        .collect();

    if contract_calls.is_empty() {
        return Some((0, 0, 0, 0));
    }

    use lattice_evm::evm::{EthClient, RPCConfig};
    let client = EthClient::default();
    let mut contract_bytecodes: Vec<(String, Vec<u8>)> = Vec::new();

    for tx in &contract_calls {
        if let Some(ref to) = tx.to {
            if !to.is_empty() {
                if let Ok(code) = client.get_code(to, &block_hex).await {
                    // Filter out problematic bytecodes:
                    // - Empty or too large
                    // - Contains DELEGATECALL/CALLCODE which can cause revm stack issues
                    // - Contains CREATE/CREATE2 which need proper sender context
                    if !code.is_empty() && code.len() < 3000 && code.len() > 2 {
                        let has_delegate = code.windows(1).any(|w| w[0] == 0xf4);
                        let has_callcode = code.windows(1).any(|w| w[0] == 0xf3);
                        let has_create = code.windows(1).any(|w| w[0] == 0xf0 || w[0] == 0xf5);
                        if !has_delegate && !has_callcode && !has_create {
                            contract_bytecodes.push((to.clone(), code));
                        }
                    }
                }
            }
        }
    }

    if contract_bytecodes.is_empty() {
        return Some((0, 0, 0, 0));
    }

    // Generate traces
    let mut total_trace_rows = 0;
    let mut total_gas_used = 0u64;
    let mut failed_traces = 0;

    for (_, code) in &contract_bytecodes {
        let gas_limit = if code.len() > 1000 { 3_000_000 } else if code.len() > 100 { 1_000_000 } else { 500_000 };

        // Execute in spawned thread to isolate crashes - revm non-unwinding panics abort the thread
        let code = code.clone();
        let result = std::thread::Builder::new()
            .name("trace-worker".to_string())
            .spawn(move || execute_evm_with_trace(&code, &[], gas_limit));

        match result {
            Ok(handle) => {
                match handle.join() {
                    Ok(Ok((state_diff, trace))) => {
                        total_trace_rows += trace.len();
                        total_gas_used += state_diff.gas_used;
                    }
                    _ => {
                        failed_traces += 1;
                    }
                }
            }
            Err(_) => {
                failed_traces += 1;
            }
        }
    }

    Some((contract_bytecodes.len(), total_trace_rows, failed_traces, total_gas_used))
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
    let mut last_processed_block = Arc::new(AtomicU64::new(0));
    let mut total_blocks = 0u64;
    let mut total_contracts = 0usize;
    let mut total_traces = 0usize;
    let mut total_failed = 0usize;
    let total_blocks_atomic = Arc::new(AtomicU64::new(0));

    // Shared state for showing block status
    let status_current = Arc::new(AtomicU64::new(initial_current));
    let status_processing = Arc::new(AtomicU64::new(0));

    println!("📊 Starting from block #{} (will poll for newer blocks)\n", current_block);

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

                        print!("\r🔄 Polling... newest={:>8} processing={:>8}    ",
                            newest_block, block_to_process);
                        std::io::Write::flush(&mut std::io::stdout()).ok();

                        match process_block(block_to_process).await {
                            Some((contracts, traces, failed, gas)) => {
                                if contracts > 0 {
                                    println!("\n✅ Block #{:>8} | {:>4} contracts | {:>5} traces | {} gas",
                                        block_to_process, contracts, traces, gas);
                                } else {
                                    println!("\n⏭️  Block #{:>8} | empty (no contract calls)", block_to_process);
                                }

                                total_contracts += contracts;
                                total_traces += traces;
                                total_failed += failed;
                                total_blocks += 1;
                                total_blocks_atomic.fetch_add(1, Ordering::SeqCst);
                                last_processed_block.store(block_to_process, Ordering::SeqCst);
                            }
                            None => {
                                println!("\n⚠️  Block #{:>8} | FAILED", block_to_process);
                            }
                        }

                        current_block = block_to_process;

                        // Check if we've reached max blocks
                        if let Some(max) = config.max_blocks {
                            if total_blocks >= max {
                                println!();
                                println!("📊 Reached maximum blocks limit ({})", max);
                                break;
                            }
                        }
                    }
                } else {
                    // No new blocks yet
                    print!("\r🔄 Waiting for new blocks... last={:>8} current={:>8}", current_block, newest_block);
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                }
            }
            Err(e) => {
                print!("\r⚠️  RPC error: {}                                                   ", e);
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
        }

        // Wait before polling again
        thread::sleep(std::time::Duration::from_millis(config.poll_interval_ms));
    }

    // Final summary
    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!();
    println!("📊 REAL-TIME PROVING SUMMARY");
    println!();
    println!("   Last processed block: #{}", last_processed_block.load(Ordering::SeqCst));
    println!("   Blocks processed: {}", total_blocks);
    println!("   Total contracts: {}", total_contracts);
    println!("   Total traces: {}", total_traces);
    println!("   Failed traces: {}", total_failed);
    if total_blocks > 0 {
        println!();
        println!("   📈 Averages:");
        println!("      • Contracts/block: {:.1}", total_contracts as f64 / total_blocks as f64);
        println!("      • Traces/block: {:.1}", total_traces as f64 / total_blocks as f64);
    }
    println!();
}
