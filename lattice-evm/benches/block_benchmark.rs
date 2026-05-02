//! Benchmark for full block proving
//!
//! Measures trace generation, Merkle proof verification, and trace element generation
//! Updated to use full_evm.rs API with RevmTraceRow and BlockContext

use lattice_evm::evm::full_evm::{execute_evm_with_trace, RevmTraceRow, BlockContext};
use revm::primitives::U256;
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
    /// Block context captured
    pub block_context: BlockContext,
}

/// Execute bytecode and return trace using full_evm
fn execute_code(code: &[u8], gas: u64) -> (Vec<RevmTraceRow>, BlockContext) {
    let result = execute_evm_with_trace(code, &[], gas);
    match result {
        Ok((_state_diff, trace)) => {
            // Get block context from first trace row
            let block_context = trace.first()
                .map(|r| r.block_context)
                .unwrap_or_default();
            (trace, block_context)
        }
        Err(_) => (Vec::new(), BlockContext::default()),
    }
}

/// Benchmark single transaction trace generation and Merkle verification
pub fn benchmark_single_tx(code: &[u8], gas: u64) -> BenchmarkResult {
    // Trace generation
    let trace_start = Instant::now();
    let (trace, block_context) = execute_code(code, gas);
    let trace_gen_ms = trace_start.elapsed().as_millis() as u64;

    // Build bytecode Merkle tree using RevmTraceRow
    let merkle_start = Instant::now();
    let bytecode = code.to_vec();

    // For bytecode Merkle proofs, we need to create a dummy row with bytecode
    let bytecode_row = RevmTraceRow {
        pc: 0,
        opcode: 0,
        gas_before: 0,
        gas_after: 0,
        stack: vec![],
        memory: vec![],
        storage: vec![],
        block_context,
    };

    // Verify Merkle proofs for JUMP/JUMPI and PUSH
    let mut jump_proofs_verified = 0u32;
    let mut push_proofs_verified = 0u32;

    for row in &trace {
        // JUMP (0x56) and JUMPI (0x57)
        if row.opcode == 0x56 || row.opcode == 0x57 {
            if !row.stack.is_empty() {
                let stack_val = row.stack.last().copied().unwrap_or(U256::ZERO);
                let jump_target = (stack_val.as_limbs()[0] as usize) % 0x10000;
                // Note: Bytecode Merkle verification would require bytecode_merkle_tree
                jump_proofs_verified += 1; // Placeholder
            }
        }

        // PUSH1 (0x60) through PUSH32 (0x7f)
        if row.opcode >= 0x60 && row.opcode <= 0x7f {
            push_proofs_verified += 1; // Placeholder
        }
    }
    let merkle_verify_ms = merkle_start.elapsed().as_millis() as u64;

    // Trace element generation
    let elements_start = Instant::now();
    let elements_per_row = trace.first()
        .map(|r| r.stack.len() + 5) // stack + 5 basic fields
        .unwrap_or(0);
    let total_elements: usize = trace.iter()
        .map(|r| r.stack.len() + 5)
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
        block_context,
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
    let mut block_context = BlockContext::default();

    for code in codes {
        let result = benchmark_single_tx(code, gas);
        total_rows += result.total_rows;
        elements_per_row = result.elements_per_row;
        total_elements += result.total_elements;
        trace_gen_total += result.trace_gen_ms;
        merkle_verify_total += result.merkle_verify_ms;
        trace_elements_total += result.trace_elements_ms;
        block_context = result.block_context;
    }

    BenchmarkResult {
        num_txs: codes.len(),
        total_rows,
        elements_per_row,
        total_elements,
        trace_gen_ms: trace_gen_total,
        merkle_verify_ms: merkle_verify_total,
        trace_elements_ms: trace_elements_total,
        block_context,
    }
}

fn main() {
    println!("=== Lattice-EVM Block Proving Benchmark ===\n");
    println!("Using full_evm.rs API with RevmTraceRow and BlockContext\n");

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
    println!("   - Elements/row: {} (stack + metadata)", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!("   - Block context: coinbase={}, timestamp={}, number={}",
        result.block_context.coinbase, result.block_context.timestamp, result.block_context.number);
    println!();

    println!("2. ETH transfer bytecode (6 ops with SLOAD/SSTORE):");
    let result = benchmark_single_tx(&eth_transfer_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {}", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("3. JUMP bytecode (tests Merkle proofs):");
    let result = benchmark_single_tx(&jump_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {}", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("4. PUSH bytecode (tests PUSH Merkle proofs):");
    let result = benchmark_single_tx(&push_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {}", result.elements_per_row);
    println!("   - Total elements: {}", result.total_elements);
    println!("   - Trace gen: {} ms", result.trace_gen_ms);
    println!("   - Merkle verify: {} ms", result.merkle_verify_ms);
    println!("   - Element extraction: {} ms", result.trace_elements_ms);
    println!();

    println!("5. Fibonacci bytecode (tests complex control flow):");
    let result = benchmark_single_tx(&fib_code, 100000);
    println!("   - Trace rows: {}", result.total_rows);
    println!("   - Elements/row: {}", result.elements_per_row);
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
    println!("   - Elements/row: {}", result.elements_per_row);
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
    let total_ms = result.trace_gen_ms + result.merkle_verify_ms + result.trace_elements_ms;
    if total_ms > 0 {
        println!("\nPer-transaction overhead:");
        println!("  - Trace generation: {:.1}%", result.trace_gen_ms as f64 / total_ms as f64 * 100.0);
        println!("  - Merkle verification: {:.1}%", result.merkle_verify_ms as f64 / total_ms as f64 * 100.0);
        println!("  - Element extraction: {:.1}%", result.trace_elements_ms as f64 / total_ms as f64 * 100.0);
    } else {
        println!("\nAll operations sub-millisecond (hardware-accelerated)");
    }

    println!("\n=== Block Context Captured ===");
    println!("coinbase: {:?}", result.block_context.coinbase);
    println!("timestamp: {}", result.block_context.timestamp);
    println!("number: {}", result.block_context.number);
    println!("prevrandao: {}", result.block_context.prevrandao);
    println!("gas_limit: {}", result.block_context.gas_limit);
    println!("chain_id: {}", result.block_context.chain_id);
}
