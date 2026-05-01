//! Contract Failure Analyzer
//!
//! Identifies WHY real contracts fail during proving.

use lattice_evm::evm::{execute_bytecode, EthClient, EthereumBlock, get_current_block_number};
use std::time::Instant;

#[tokio::main]
async fn main() {
    println!("=== Contract Failure Analyzer ===\n");

    let block_num = match get_current_block_number().await {
        Ok(n) => { println!("Current block: #{}\n", n); n }
        Err(e) => { println!("Failed to get block: {}", e); return; }
    };

    println!("Fetching block #{}...", block_num);
    let block = match EthereumBlock::fetch(block_num).await {
        Ok(b) => b,
        Err(e) => { println!("Failed to fetch block: {}", e); return; }
    };

    let hex_number = format!("0x{:x}", block_num);

    // Get contract codes
    println!("\nFetching contract bytecode...");
    let mut contracts: Vec<(String, Vec<u8>)> = Vec::new();

    for tx in &block.transactions {
        if tx.input.is_empty() || tx.input == "0x" {
            continue;
        }
        if let Some(ref to) = tx.to {
            if !to.is_empty() {
                let client = EthClient::default();
                match client.get_code(to, &hex_number).await {
                    Ok(code) if !code.is_empty() && code.len() < 50000 => {
                        contracts.push((to.clone(), code));
                    }
                    _ => {}
                }
            }
        }
    }

    println!("Found {} contract calls\n", contracts.len());

    // Analyze first 20 contracts
    let to_analyze = contracts.iter().take(20).collect::<Vec<_>>();
    println!("Analyzing first {} contracts...\n", to_analyze.len());

    let mut success_count = 0;
    let mut fail_count = 0;
    let mut fail_reasons: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for (i, (addr, code)) in to_analyze.iter().enumerate() {
        let start = Instant::now();
        let exec_result = execute_bytecode(code, 1_000_000);
        let exec_time = start.elapsed().as_millis();

        println!("{}. {} ({} bytes):", i, &addr[..10], code.len());

        match exec_result {
            Ok((state, trace)) => {
                success_count += 1;
                println!("  ✓ SUCCESS: pc={}, gas={}, stack={}, trace={} rows ({:.1}ms)",
                    state.pc, state.gas, state.stack.len(), trace.len(), exec_time);

                // Analyze trace quality
                if trace.is_empty() {
                    println!("    WARNING: Empty trace!");
                }
                if !state.running && !state.reverted {
                    println!("    Note: Stopped gracefully");
                }
                if state.reverted {
                    println!("    Note: Reverted");
                }
            }
            Err(e) => {
                fail_count += 1;
                *fail_reasons.entry(e.to_string()).or_insert(0) += 1;
                println!("  ✗ FAILED: {} ({:.1}ms)", e, exec_time);
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total analyzed: {}", to_analyze.len());
    println!("  ✓ Success: {} ({:.1}%)", success_count, (success_count as f64 / to_analyze.len() as f64) * 100.0);
    println!("  ✗ Failed: {} ({:.1}%)", fail_count, (fail_count as f64 / to_analyze.len() as f64) * 100.0);

    if !fail_reasons.is_empty() {
        println!("\nFailure reasons:");
        for (reason, count) in fail_reasons.iter() {
            println!("  {}: {} contracts", reason, count);
        }
    }

    // Estimate full block performance
    println!("\n=== Full Block Estimate ===");
    let success_rate = success_count as f64 / (success_count + fail_count) as f64;
    let total_contracts = contracts.len();
    let valid_contracts = (total_contracts as f64 * success_rate) as usize;

    println!("Total contracts in block: {}", total_contracts);
    println!("Expected valid (based on sample): {} ({:.1}%)",
        valid_contracts, success_rate * 100.0);

    // Test with a few more block numbers
    println!("\n=== Block History Comparison ===");

    for offset in [0, 100, 1000, 10000] {
        let check_block = block_num.saturating_sub(offset);
        print!("Block #{:010}: ", check_block);

        match EthereumBlock::fetch(check_block).await {
            Ok(b) => {
                let transfers = b.transactions.iter().filter(|t| t.input.is_empty() || t.input == "0x").count();
                let contracts = b.transactions.len() - transfers;
                println!(" {} txs ({} transfers, {} contracts)",
                    b.transactions.len(), transfers, contracts);
            }
            Err(e) => println!(" fetch failed: {}", e),
        }
    }
}