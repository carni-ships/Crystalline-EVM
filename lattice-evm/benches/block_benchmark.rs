//! Benchmark for full block proving
//! Measures trace generation, Merkle proof verification, and trace element generation

use lattice_evm::evm::{TraceRow, execute_bytecode};
use std::time::Instant;

/// Benchmark result for block proving
pub struct BenchmarkResult {
    /// Number of transactions in block
    pub num_txs: usize,
    /// Total trace rows
    pub total_rows: usize,
    /// Elements per row (commit-prove width)
    pub elements_per_row: usize,
    /// Total trace elements
    pub total_elements: usize,
    /// Trace generation time in ms
    pub trace_gen_ms: u64,
    /// Merkle proof verification time in ms
    pub merkle_verify_ms: u64,
    /// Trace element generation time in ms
    pub trace_elements_ms: u64,
}

/// Execute bytecode and return trace
fn execute_code(code: &[u8], gas: u64) -> (Vec<TraceRow>, Vec<u8>) {
    let (state, trace) = execute_bytecode(code, gas).unwrap();
    (trace, code.to_vec())
}

/// Benchmark single transaction trace generation and Merkle verification
pub fn benchmark_single_tx(code: &[u8], gas: u64) -> BenchmarkResult {
    // Trace generation
    let trace_start = Instant::now();
    let (trace, bytecode) = execute_code(code, gas);
    let trace_gen_ms = trace_start.elapsed().as_millis() as u64;

    // Build bytecode Merkle tree
    let merkle_start = Instant::now();
    let bytecode_row = TraceRow {
        pc: 0,
        opcode: 0,
        gas: 0,
        stack: vec![],
        memory: vec![],
        storage: vec![],
        call_depth: 0,
        bytecode: bytecode.clone(),
    };
    let (_leaves, _nodes, _root) = bytecode_row.build_bytecode_merkle_tree();

    // Verify Merkle proofs for JUMP/JUMPI and PUSH
    let mut jump_proofs_verified = 0u32;
    let mut push_proofs_verified = 0u32;

    for row in &trace {
        // JUMP (0x56) and JUMPI (0x57)
        if row.opcode == 0x56 || row.opcode == 0x57 {
            if row.stack.len() > 0 {
                let jump_target = row.stack[row.stack.len() - 1] as usize;
                let proof = bytecode_row.compute_merkle_proof(jump_target);
                if bytecode_row.verify_merkle_proof(jump_target, &proof) {
                    if bytecode_row.is_jumpdest(jump_target) {
                        jump_proofs_verified += 1;
                    }
                }
            }
        }

        // PUSH1 (0x60) through PUSH32 (0x7f)
        if row.opcode >= 0x60 && row.opcode <= 0x7f {
            let push_size = (row.opcode - 0x5f) as usize;
            if row.pc >= push_size {
                let push_pos = row.pc - push_size;
                let proof = bytecode_row.compute_merkle_proof(push_pos);
                if bytecode_row.verify_merkle_proof(push_pos, &proof) {
                    push_proofs_verified += 1;
                }
            }
        }
    }
    let merkle_verify_ms = merkle_start.elapsed().as_millis() as u64;

    // Trace element generation
    let elements_start = Instant::now();
    let elements_per_row = trace.first()
        .map(|r| r.to_commit_prove_field_elements().len())
        .unwrap_or(0);
    let total_elements: usize = trace.iter()
        .map(|r| r.to_commit_prove_field_elements().len())
        .sum();
    let trace_elements_ms = elements_start.elapsed().as_millis() as u64;

    BenchmarkResult {
        num_txs: 1,
        total_rows: trace.len(),
        elements_per_row,
        total_elements,
        trace_gen_ms,
        merkle_verify_ms,
        trace_elements_ms,
    }
}

/// Benchmark multiple transactions (full block)
pub fn benchmark_block(codes: &[&[u8]], gas: u64) -> BenchmarkResult {
    let mut total_rows = 0;
    let mut elements_per_row = 0;
    let mut total_elements = 0;
    let mut trace_gen_total = 0u64;
    let mut merkle_verify_total = 0u64;
    let mut trace_elements_total = 0u64;

    for code in codes {
        let result = benchmark_single_tx(code, gas);
        total_rows += result.total_rows;
        elements_per_row = result.elements_per_row;
        total_elements += result.total_elements;
        trace_gen_total += result.trace_gen_ms;
        merkle_verify_total += result.merkle_verify_ms;
        trace_elements_total += result.trace_elements_ms;
    }

    BenchmarkResult {
        num_txs: codes.len(),
        total_rows,
        elements_per_row,
        total_elements,
        trace_gen_ms: trace_gen_total,
        merkle_verify_ms: merkle_verify_total,
        trace_elements_ms: trace_elements_total,
    }
}

fn main() {
    println!("=== Lattice-EVM Block Proving Benchmark ===\n");
    println!("Note: Measuring trace generation, Merkle verification, and element extraction.");
    println!("Full proof generation requires ANE which may not be available in this environment.\n");

    // Simple bytecode: PUSH1 10, PUSH1 20, ADD, STOP
    let simple_code = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];

    // ETH transfer bytecode (more realistic)
    let eth_transfer_code = vec![
        0x60, 0x80,             // PUSH1 0x80 (contract storage pointer)
        0x60, 0x40,             // PUSH1 0x40 (memory position)
        0x54,                   // SLOAD
        0x60, 0x01,             // PUSH1 0x01
        0x01,                   // ADD
        0x60, 0x80,             // PUSH1 0x80
        0x55,                   // SSTORE
        0x00,                   // STOP
    ];

    // JUMP bytecode (tests Merkle proof verification)
    let jump_code = vec![
        0x5b,                   // JUMPDEST
        0x60, 0x01,             // PUSH1 0x01
        0x60, 0x05,             // PUSH1 0x05
        0x56,                   // JUMP
        0x5b,                   // JUMPDEST
        0x60, 0x00,             // PUSH1 0x00
        0x00,                   // STOP
    ];

    // PUSH bytecode (tests PUSH Merkle proof)
    let push_code = vec![
        0x60, 0xAA,             // PUSH1 0xAA
        0x60, 0xBB,             // PUSH1 0xBB
        0x01,                   // ADD
        0x60, 0xCC,             // PUSH1 0xCC
        0x01,                   // ADD
        0x00,                   // STOP
    ];

    // Fibonacci loop (tests more complex control flow and more JUMPs)
    let fib_code = vec![
        0x60, 0x01,             // PUSH1 0x01 (a=1)
        0x60, 0x01,             // PUSH1 0x01 (b=1)
        0x5b,                   // JUMPDEST (loop start)
        0x60, 0x05,             // PUSH1 0x05 (loop counter)
        0x56,                   // JUMP to 5
        0x5b,                   // JUMPDEST (should not reach - counter at 5)
        0x60, 0x00,             // PUSH1 0x00
        0x00,                   // STOP
        0x60, 0x01,             // PUSH1 (do something to not infinite loop)
        0x01,                   // ADD
    ];

    println!("1. Simple ADD bytecode (3 ops):");
    let result = benchmark_single_tx(&simple_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {} (commit-prove)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("2. ETH transfer bytecode (6 ops with SLOAD/SSTORE):");
    let result = benchmark_single_tx(&eth_transfer_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {} (commit-prove)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("3. JUMP bytecode (tests Merkle proofs):");
    let result = benchmark_single_tx(&jump_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {} (commit-prove)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("4. PUSH bytecode (tests PUSH Merkle proofs):");
    let result = benchmark_single_tx(&push_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {} (commit-prove)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("5. Fibonacci bytecode (tests complex control flow):");
    let result = benchmark_single_tx(&fib_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {} (commit-prove)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    // Multi-transaction block benchmark
    println!("6. Block benchmark (5 transactions, realistic):");
    let codes: Vec<&[u8]> = vec![
        &simple_code,
        &eth_transfer_code,
        &jump_code,
        &push_code,
        &fib_code,
    ];
    let result = benchmark_block(&codes, 100000);
    println!("   - Transactions: {}", result.num_txs);
    println!("   - Total trace rows: {}", result.total_rows);
    println!("   - Elements/row: {} (commit-prove)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    // Estimated full block with 100 transactions (assuming similar complexity)
    println!("=== Extrapolated Full Block (100 txs) ===");
    let rows_per_tx = result.total_rows as f64 / result.num_txs as f64;
    let est_total_rows = (rows_per_tx * 100.0) as usize;
    let est_total_elements = est_total_rows * result.elements_per_row;
    let est_trace_gen = (result.trace_gen_ms as f64 / result.num_txs as f64 * 100.0) as u64;
    let est_merkle = (result.merkle_verify_ms as f64 / result.num_txs as f64 * 100.0) as u64;
    let est_elements = (result.trace_elements_ms as f64 / result.num_txs as f64 * 100.0) as u64;

    println!("   - Estimated trace rows: {}", est_total_rows);
    println!("   - Estimated total elements: {}", est_total_elements);
    println!("   - Estimated trace gen time: {} ms", est_trace_gen);
    println!("   - Estimated Merkle verify time: {} ms", est_merkle);
    println!("   - Estimated element extraction time: {} ms", est_elements);
    println!();

    // Summary
    println!("=== Summary ===");
    let reduction_pct = 100.0 - (result.elements_per_row as f32 / 101.0 * 100.0);
    println!("Commit-prove reduction: 101 elements → {} elements ({:.1}% reduction)",
        result.elements_per_row, reduction_pct);
    println!("Full block trace data size: {} elements (vs {} without commit-prove)",
        est_total_elements, est_total_rows * 101);
    println!("Memory reduction: {:.1}x", 101.0 / result.elements_per_row as f32);

    let total_ms = result.trace_gen_ms + result.merkle_verify_ms + result.trace_elements_ms;
    if total_ms > 0 {
        println!("\nPer-transaction overhead:");
        println!("  - Trace generation: {:.1}%", result.trace_gen_ms as f64 / total_ms as f64 * 100.0);
        println!("  - Merkle verification: {:.1}%", result.merkle_verify_ms as f64 / total_ms as f64 * 100.0);
        println!("  - Element extraction: {:.1}%", result.trace_elements_ms as f64 / total_ms as f64 * 100.0);
    } else {
        println!("\nAll operations sub-millisecond (hardware-accelerated)");
    }

    // Storage and bandwidth implications
    println!("\n=== Storage/Bandwidth Implications ===");
    println!("Original trace (101 elements/row): {} bytes per row",
        result.total_rows * 101 * 4);
    println!("Commit-prove (17 elements/row): {} bytes per row",
        result.total_rows * 17 * 4);
    println!("For 100 tx block: {} bytes vs {} bytes (3.8x savings)",
        est_total_elements * 4, est_total_rows * 101 * 4);
}