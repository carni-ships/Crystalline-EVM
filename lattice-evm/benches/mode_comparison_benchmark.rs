//! Mode comparison benchmark
//!
//! Compares simplified (RevmTraceRow) vs full (TraceRow) trace modes
//! on the same bytecode to measure performance and element count differences.

use lattice_evm::evm::full_evm::{execute_evm_with_trace, RevmTraceRow};
use lattice_evm::evm::{execute_bytecode, TraceRow};
use lattice_evm::prover::{Prover, ProverConfig};
use std::time::Instant;

const WITNESS_SIZE: usize = 256;

/// Extract elements from RevmTraceRow (simplified mode)
fn extract_revm_elements(trace: &[RevmTraceRow]) -> Vec<u32> {
    let mut elements = Vec::new();
    for row in trace {
        elements.push(row.pc as u32 % 8383489);
        elements.push(row.opcode as u32);
        elements.push((row.gas_before % 8383489) as u32);
        elements.push((row.gas_after % 8383489) as u32);
        elements.push(row.stack.len() as u32 % 8383489);
        for val in &row.stack {
            elements.push((val.as_limbs()[0] % 8383489) as u32);
        }
    }
    elements
}

/// Extract elements from TraceRow (full mode)
fn extract_full_elements(trace: &[TraceRow]) -> Vec<u32> {
    let mut elements = Vec::new();
    for row in trace {
        // Basic info (5)
        elements.push(row.pc as u32 % 8383489);
        elements.push(row.opcode as u32);
        elements.push((row.gas_before % 8383489) as u32);
        elements.push((row.gas_after % 8383489) as u32);
        elements.push(row.stack.len() as u32 % 8383489);

        // Stack values (up to 16)
        for &val in row.stack.iter().take(16) {
            elements.push(val % 8383489);
        }
        for _ in row.stack.len()..16 {
            elements.push(0);
        }

        // Memory size (1)
        elements.push(row.memory.len() as u32 % 8383489);

        // Storage count (1)
        elements.push(row.storage.len() as u32 % 8383489);

        // Call depth (1)
        elements.push(row.call_depth as u32 % 8383489);

        // Memory ops (up to 4 pairs = 8 elements)
        for &(offset, val) in row.memory_ops.iter().take(4) {
            elements.push(offset % 8383489);
            elements.push(val % 8383489);
        }
        for _ in row.memory_ops.len()..4 {
            elements.push(0);
            elements.push(0);
        }

        // Storage ops (up to 4 pairs = 8 elements)
        for &(key, val) in row.storage_ops.iter().take(4) {
            elements.push(key % 8383489);
            elements.push(val % 8383489);
        }
        for _ in row.storage_ops.len()..4 {
            elements.push(0);
            elements.push(0);
        }
    }
    elements
}

fn run_simplified(codes: &[&[u8]]) -> (usize, usize, f64, f64, f64, usize, usize, usize, usize) {
    let trace_start = Instant::now();
    let traces: Vec<Vec<RevmTraceRow>> = codes.iter()
        .map(|code| {
            let gas_limit = if code.len() > 2000 { 2_000_000 } else if code.len() > 500 { 1_000_000 } else { 500_000 };
            let result = execute_evm_with_trace(code, &[], gas_limit);
            result.map(|(_, t)| t).unwrap_or_default()
        })
        .collect();
    let trace_ms = trace_start.elapsed().as_secs_f64() * 1000.0;

    let total_rows: usize = traces.iter().map(|t| t.len()).sum();
    let elements: Vec<u32> = traces.iter().flat_map(|t| extract_revm_elements(t)).collect();

    let commit_start = Instant::now();
    let batches: Vec<Vec<u32>> = elements.chunks(WITNESS_SIZE)
        .map(|chunk| {
            let mut batch = chunk.to_vec();
            while batch.len() < WITNESS_SIZE {
                batch.push(0);
            }
            batch
        })
        .collect();
    let commit_ms = commit_start.elapsed().as_secs_f64() * 1000.0;

    let prove_start = Instant::now();
    let config = ProverConfig::default();
    let mut prove_count = 0;
    let mut prove_errors = 0;
    let mut verify_success = 0;
    let mut verify_failures = 0;

    if let Ok(prover) = Prover::new(config) {
        for batch in &batches {
            let witness: Vec<f32> = batch.iter().map(|&v| v as f32).collect();
            match prover.prove_witness(&witness) {
                Ok(proof) => {
                    prove_count += 1;
                    match prover.verify_proof(&proof) {
                        Ok(true) => verify_success += 1,
                        Ok(false) => verify_failures += 1,
                        Err(_) => verify_failures += 1,
                    }
                }
                Err(_) => prove_errors += 1,
            }
        }
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    (total_rows, elements.len(), trace_ms, commit_ms, prove_ms, prove_count, prove_errors, verify_success, verify_failures)
}

fn run_full(codes: &[&[u8]]) -> (usize, usize, f64, f64, f64, usize, usize, usize, usize) {
    let trace_start = Instant::now();
    let traces: Vec<Vec<TraceRow>> = codes.iter()
        .map(|code| {
            let gas_limit = if code.len() > 2000 { 2_000_000 } else if code.len() > 500 { 1_000_000 } else { 500_000 };
            let result = execute_bytecode(code, gas_limit);
            result.map(|(_, t)| t).unwrap_or_default()
        })
        .collect();
    let trace_ms = trace_start.elapsed().as_secs_f64() * 1000.0;

    let total_rows: usize = traces.iter().map(|t| t.len()).sum();
    let elements: Vec<u32> = traces.iter().flat_map(|t| extract_full_elements(t)).collect();

    let commit_start = Instant::now();
    let batches: Vec<Vec<u32>> = elements.chunks(WITNESS_SIZE)
        .map(|chunk| {
            let mut batch = chunk.to_vec();
            while batch.len() < WITNESS_SIZE {
                batch.push(0);
            }
            batch
        })
        .collect();
    let commit_ms = commit_start.elapsed().as_secs_f64() * 1000.0;

    let prove_start = Instant::now();
    let config = ProverConfig::default();
    let mut prove_count = 0;
    let mut prove_errors = 0;
    let mut verify_success = 0;
    let mut verify_failures = 0;

    if let Ok(prover) = Prover::new(config) {
        for batch in &batches {
            let witness: Vec<f32> = batch.iter().map(|&v| v as f32).collect();
            match prover.prove_witness(&witness) {
                Ok(proof) => {
                    prove_count += 1;
                    match prover.verify_proof(&proof) {
                        Ok(true) => verify_success += 1,
                        Ok(false) => verify_failures += 1,
                        Err(_) => verify_failures += 1,
                    }
                }
                Err(_) => prove_errors += 1,
            }
        }
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    (total_rows, elements.len(), trace_ms, commit_ms, prove_ms, prove_count, prove_errors, verify_success, verify_failures)
}

fn main() {
    println!("=== EVM Trace Mode Comparison ===\n");

    // Test bytecodes of varying complexity
    let test_cases: Vec<(&str, Vec<u8>)> = vec![
        ("Simple ADD", vec![0x60, 0x01, 0x60, 0x00, 0x01, 0x00]),
        ("Storage ops", vec![0x60, 0x80, 0x60, 0x40, 0x54, 0x60, 0x01, 0x01, 0x60, 0x80, 0x55, 0x00]),
        ("JUMP", vec![0x5b, 0x60, 0x01, 0x60, 0x05, 0x56, 0x5b, 0x60, 0x00, 0x00]),
        ("PUSH sequence", vec![0x60, 0xAA, 0x60, 0xBB, 0x01, 0x60, 0xCC, 0x01, 0x00]),
        ("Fibonacci loop", vec![0x60, 0x01, 0x60, 0x01, 0x5b, 0x60, 0x05, 0x56, 0x5b, 0x60, 0x00, 0x00, 0x60, 0x01, 0x01]),
        ("CALL value", vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0xf1, 0x00]),
        ("CREATE", vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x00]),
        ("Memory expand", vec![0x60, 0x01, 0x60, 0x01, 0x52, 0x60, 0x20, 0x60, 0x00, 0x51, 0x00]),
    ];

    let code_refs: Vec<&[u8]> = test_cases.iter().map(|(_, v)| v.as_slice()).collect();

    println!("Running Simplified mode (RevmTraceRow)...\n");
    let (simp_rows, simp_elements, simp_trace, simp_commit, simp_prove, simp_count, simp_errors, simp_verify_ok, simp_verify_fail) = run_simplified(&code_refs);

    println!("\nRunning Full mode (TraceRow)...\n");
    let (full_rows, full_elements, full_trace, full_commit, full_prove, full_count, full_errors, full_verify_ok, full_verify_fail) = run_full(&code_refs);

    // Comparison
    println!("\n╔════════════════════════════════════════════════════════════════════╗");
    println!("║                        COMPARISON SUMMARY                            ║");
    println!("╠════════════════════════════════════════════════════════════════════╣");
    println!("║ Metric              │ Simplified    │ Full        │ Ratio        ║");
    println!("╠════════════════════════════════════════════════════════════════════╣");
    println!("║ Trace rows          │ {:12}   │ {:10}   │ {:.2}x         ║", simp_rows, full_rows, full_rows as f64 / simp_rows as f64);
    println!("║ Elements/row        │ {:12.1}   │ {:10.1}   │ {:.2}x         ║", simp_elements as f64 / simp_rows as f64, full_elements as f64 / full_rows as f64, (full_elements as f64 / full_rows as f64) / (simp_elements as f64 / simp_rows as f64));
    println!("║ Total elements      │ {:12}   │ {:10}   │ {:.2}x         ║", simp_elements, full_elements, full_elements as f64 / simp_elements as f64);
    println!("║ Batches (L=256)     │ {:12}   │ {:10}   │ {:.2}x         ║", simp_elements / 256, full_elements / 256, (full_elements / 256) as f64 / (simp_elements / 256) as f64);
    println!("║ TRACE time (ms)     │ {:12.3}   │ {:10.3}   │ {:.2}x         ║", simp_trace, full_trace, full_trace / simp_trace);
    println!("║ COMMIT time (ms)    │ {:12.3}   │ {:10.3}   │ {:.2}x         ║", simp_commit, full_commit, full_commit / simp_commit);
    println!("║ PROVE time (ms)     │ {:12.3}   │ {:10.3}   │ {:.2}x         ║", simp_prove, full_prove, full_prove / simp_prove);
    println!("╚════════════════════════════════════════════════════════════════════╝");

    println!("\nProof results: Simplified {}/{} (verified {}/{}), Full {}/{} (verified {}/{})",
        simp_count, simp_count + simp_errors, simp_verify_ok, simp_verify_ok + simp_verify_fail,
        full_count, full_count + full_errors, full_verify_ok, full_verify_ok + full_verify_fail);
}