//! Debug Failed Contracts
//!
//! Investigates why certain contracts fail during execution.
//! Tests with varying gas limits and captures error patterns.

use lattice_evm::evm::{execute_bytecode, EVMState, TraceRow};
use std::time::Instant;

fn execute_with_gas(code: &[u8], gas: u64) -> Result<(EVMState, Vec<TraceRow>), String> {
    execute_bytecode(code, gas).map_err(|e| e.to_string())
}

fn analyze_contract(code: &[u8], name: &str, gas: u64) {
    let start = Instant::now();
    let result = execute_with_gas(code, gas);
    let elapsed = start.elapsed().as_millis();

    match result {
        Ok((state, trace)) => {
            println!("  ✓ {}: pc={}, gas={}, stack={}, trace_rows={} ({}ms)",
                name, state.pc, state.gas, state.stack.len(), trace.len(), elapsed);
        }
        Err(e) => {
            println!("  ✗ {}: {} ({}ms)", name, e, elapsed);
        }
    }
}

fn main() {
    let start = Instant::now();
    let result = execute_with_gas(code, gas);
    let elapsed = start.elapsed().as_millis();

    match result {
        Ok((state, trace)) => {
            println!("  ✓ {}: pc={}, gas={}, stack={}, trace_rows={} ({}ms)",
                name, state.pc, state.gas, state.stack.len(), trace.len(), elapsed);
        }
        Err(e) => {
            println!("  ✗ {}: {} ({}ms)", name, e, elapsed);
        }
    }
}

fn main() {
    println!("=== Contract Execution Debug ===\n");

    // Try different gas limits
    let gas_limits = vec![100_000, 1_000_000, 10_000_000];

    for gas in gas_limits {
        println!("\n--- Gas Limit: {} ---", gas);

        // Test simple bytecode first
        println!("Simple bytecode:");
        analyze_contract(&[0x60, 0x0A, 0x60, 0x14, 0x01, 0x00], "ADD", gas);
        analyze_contract(&[0x5b, 0x60, 0x01, 0x60, 0x05, 0x56, 0x5b, 0x60, 0x00, 0x00], "JUMP", gas);

        // Fibonacci (has JUMPDEST issue)
        analyze_contract(&[0x60, 0x01, 0x60, 0x01, 0x5b, 0x05, 0x56, 0x5b, 0x01, 0x01], "Fibonacci", gas);

        // Test medium bytecode
        println!("\nMedium bytecode (SLOAD/SSTORE):");
        analyze_contract(&[
            0x60, 0x80, 0x60, 0x40, 0x54, 0x60, 0x01, 0x01, 0x60, 0x80, 0x55, 0x00
        ], "SLOAD/SSTORE", gas);

        // Test large bytecode patterns
        println!("\nLarge bytecode pattern (repeated ADD):");
        let mut large_code = vec![0x60, 0x01]; // PUSH1 0x01
        for _ in 0..100 {
            large_code.push(0x01); // ADD
        }
        large_code.push(0x00); // STOP
        analyze_contract(&large_code, "Large loop", gas);
    }

    // Investigate bytecode size vs execution
    println!("\n=== Bytecode Size vs Execution ===\n");

    for size in [10, 100, 1000, 10000] {
        let code: Vec<u8> = (0..size).map(|i| if i % 2 == 0 { 0x60 } else { i as u8 }).collect();
        let start = Instant::now();
        match execute_with_gas(&code, 1_000_000) {
            Ok((state, trace)) => {
                println!("Size {}: pc={}, trace_rows={}, time={:.2}ms",
                    size, state.pc, trace.len(), start.elapsed().as_millis() as f64);
            }
            Err(e) => {
                println!("Size {}: FAILED - {} ({:.2}ms)",
                    size, e, start.elapsed().as_millis() as f64);
            }
        }
    }

    // Test specific problematic bytecode patterns
    println!("\n=== Testing Specific Patterns ===\n");

    // Simple SSTORE
    analyze_contract(&[0x60, 0x00, 0x60, 0x00, 0x55], "SSTORE", 1_000_000);

    // SSTORE with larger value
    analyze_contract(&[0x64, 0x01, 0x00, 0x00, 0x00, 0x60, 0x00, 0x55], "SSTORE large", 1_000_000);

    // Nested calls (CALL)
    analyze_contract(&[
        0x60, 0x01, 0x60, 0x01, 0x60, 0x00, 0xf1, 0x00  // PUSH1 1 PUSH1 1 PUSH1 0 CALL STOP
    ], "CALL", 1_000_000);

    // Revert pattern
    analyze_contract(&[
        0x60, 0x00, 0xfd  // PUSH1 0 REVERT
    ], "REVERT", 1_000_000);

    // Invalid opcode
    analyze_contract(&[
        0x60, 0x00, 0xfe  // PUSH1 0 INVALID
    ], "INVALID", 1_000_000);

    // Return datah
    analyze_contract(&[
        0x60, 0x20, 0x60, 0x00, 0xf3  // PUSH1 0x20 PUSH1 0 RETURN
    ], "RETURN", 1_000_000);

    // Create new contract
    analyze_contract(&[
        0x60, 0x0a, 0x60, 0x00, 0x40, 0xf0  // PUSH1 0x0a PUSH1 0 CREATE
    ], "CREATE", 1_000_000);
}