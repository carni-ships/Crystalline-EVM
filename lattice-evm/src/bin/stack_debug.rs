//! Detailed Stack Underflow Debugger
//!
//! Traces exactly which opcode causes stack underflow.

use lattice_evm::evm::execute_bytecode;
use std::collections::HashMap;

/// Simple wrapper that uses the actual execute_bytecode and returns error info
fn debug_contract(code: &[u8], name: &str, gas: u64) -> Result<(), String> {
    match execute_bytecode(code, gas) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{} at {}", e, name)),
    }
}

fn main() {
    println!("=== Stack Underflow Debugger ===\n");

    // Test with known failing contracts (using small snippets)
    let test_cases = vec![
        ("Empty", vec![]),
        ("STOP only", vec![0x00]),
        ("Simple ADD", vec![0x60, 0x01, 0x60, 0x01, 0x01, 0x00]),
        ("Large PUSH sequence", vec![0x60, 0x01, 0x60, 0x01, 0x60, 0x01, 0x60, 0x01, 0x60, 0x01]),
        ("Nested calls pattern", vec![
            0x60, 0x01, 0x60, 0x01, 0x60, 0x01, 0x60, 0x01, 0x60, 0x01, 0xf1, 0x00
        ]),
    ];

    println!("Testing basic patterns:");
    for (name, code) in &test_cases {
        match debug_contract(code, name, 1_000_000) {
            Ok(_) => println!("  ✓ {}", name),
            Err(e) => println!("  ✗ {}: {}", name, e),
        }
    }

    // Test USDC-like pattern
    println!("\nTesting USDC-like patterns:");
    let usdc_transfer = vec![
        0x60, 0xa0, 0x60, 0x40, 0x54, 0x5a, 0x73, 0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1,
        0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce, 0x36, 0x06, 0xeB, 0x48, 0x60, 0x00, 0x56, 0x5b, 0x60,
        0x00, 0x80, 0x60, 0x1f, 0x61, 0x00, 0x00, 0x60, 0x00, 0xf3, 0x5a, 0x60, 0x00, 0x52, 0x60, 0x80,
        0x61, 0x00, 0x00, 0x39, 0x60, 0x20, 0x60, 0x00, 0x55,
    ];
    match debug_contract(&usdc_transfer, "USDC-like", 1_000_000) {
        Ok(_) => println!("  ✓ USDC-like"),
        Err(e) => println!("  ✗ USDC-like: {}", e),
    }

    // Fetch a real block and debug specific contracts
    println!("\n=== Fetching Real Contracts ===");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let block_num = rt.block_on(lattice_evm::evm::get_current_block_number()).unwrap_or(19_000_000);

    let block = rt.block_on(lattice_evm::evm::EthereumBlock::fetch(block_num)).unwrap();
    let hex_number = format!("0x{:x}", block_num);

    // Find failing contracts
    let mut failures: Vec<(String, usize, String)> = Vec::new();

    for tx in &block.transactions {
        if tx.input.is_empty() || tx.input == "0x" {
            continue;
        }
        if let Some(ref to) = tx.to {
            if !to.is_empty() {
                let client = lattice_evm::evm::EthClient::default();
                match rt.block_on(client.get_code(to, &hex_number)) {
                    Ok(code) if !code.is_empty() && code.len() < 50000 => {
                        match debug_contract(&code, &to[..10], 1_000_000) {
                            Err(e) => failures.push((to.clone(), code.len(), e)),
                            Ok(_) => {}
                        }
                        if failures.len() >= 10 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    println!("\n=== Failures Found ===");
    let mut reason_counts: HashMap<String, usize> = HashMap::new();
    for (addr, size, reason) in &failures {
        println!("  {} ({} bytes): {}", addr, size, reason);
        *reason_counts.entry(reason.clone()).or_insert(0) += 1;
    }

    println!("\n=== Failure Reasons Summary ===");
    for (reason, count) in reason_counts {
        println!("  {}: {} contracts", reason, count);
    }
}