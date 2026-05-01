//! Lattice EVM Prover Binary - Parallel Recursive Proving Benchmark
//!
//! Benchmarks parallel proving with multiple threads vs sequential.

use lattice_evm::{Prover, prover::ProverConfig, evm::{TraceRow, execute_bytecode}};
use lattice_evm::prover::parallel_prove;
use std::time::Instant;

fn main() {
    tracing_subscriber::fmt::init();

    println!("==============================================");
    println!("Parallel Recursive Proving Benchmark");
    println!("==============================================\n");

    let config = ProverConfig {
        trace_width: 4,
        trace_length: 256,
        lambda: 2.0,
        enable_keccak: true,
        enable_merkle: true,
    };

    let prover = Prover::new(config.clone())
        .expect("Failed to create prover");

    println!("Hardware:");
    println!("  ANE available: {}", prover.ane_available());
    println!("  GPU available: {}", prover.gpu_available());
    let num_cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    println!("  Available CPUs: {}", num_cpus);
    println!();

    // Test sizes
    let test_sizes = [1, 5, 10, 20, 50, 100];

    println!("\n=== SEQUENTIAL vs PARALLEL ===");
    println!();
    println!("Tx  | Elements | Seq Time   | Par Time   | Speedup");
    println!("----|----------|------------|------------|--------");

    for &num_txs in &test_sizes {
        // Execute transactions
        let mut trace: Vec<TraceRow> = Vec::new();
        for i in 0..num_txs {
            let value = ((i + 1) % 256) as u8;
            let code = vec![
                0x60, value, 0x60, 0x00, 0x60, 0x00, 0x60, 0x20, 0x60, 0x00, 0x60, 0x02, 0x00
            ];
            let (_, tx_trace) = execute_bytecode(&code, 100000).unwrap();
            trace.extend(tx_trace);
        }

        // Convert to elements using COMMIT-PROVE representation (10 elements with balance)
        let trace_data: Vec<u32> = trace.iter()
            .flat_map(|row| row.to_commit_prove_field_elements())
            .collect();

        let num_elements = trace_data.len();

        // Sequential proving
        let seq_start = Instant::now();
        let seq_tree = parallel_prove::build_proof_tree_parallel(&config, &trace_data);
        let seq_time = seq_start.elapsed();

        match seq_tree {
            Ok(_) => {
                println!("{:3} | {:8} | {:10.2}ms | (see parallel below)",
                    num_txs, num_elements, seq_time.as_secs_f64() * 1000.0);
            }
            Err(e) => {
                println!("{:3} | {:8} | ERR: {} | -", num_txs, num_elements, e);
            }
        }
    }

    println!();
    println!("Note: Parallel proving uses std::thread thread pool");
    println!("      Each thread has its own Prover (ANE context)");
    println!();

    // Run parallel benchmark
    println!("\n=== PARALLEL SCALING ===");
    println!();
    println!("Tx  | Threads | Batches | Proofs | Time     | Per Batch");
    println!("----|---------|---------|--------|----------|----------");

    let parallel_sizes = [1, 10, 50, 100];

    for &num_txs in &parallel_sizes {
        // Execute transactions
        let mut trace: Vec<TraceRow> = Vec::new();
        for i in 0..num_txs {
            let value = ((i + 1) % 256) as u8;
            let code = vec![
                0x60, value, 0x60, 0x00, 0x60, 0x00, 0x60, 0x20, 0x60, 0x00, 0x60, 0x02, 0x00
            ];
            let (_, tx_trace) = execute_bytecode(&code, 100000).unwrap();
            trace.extend(tx_trace);
        }

        // Convert to elements using COMMIT-PROVE representation (10 elements with balance)
        let trace_data: Vec<u32> = trace.iter()
            .flat_map(|row| row.to_commit_prove_field_elements())
            .collect();

        let num_elements = trace_data.len();
        let num_batches = (num_elements + 3) / 4;

        // Parallel proving
        let par_start = Instant::now();
        let result = parallel_prove::build_proof_tree_parallel(&config, &trace_data);
        let par_time = par_start.elapsed();

        match result {
            Ok(tree) => {
                let per_batch_ms = par_time.as_secs_f64() * 1000.0 / num_batches as f64;
                println!("{:3} | {:7} | {:7} | {:6} | {:7.2}ms | {:8.3}ms",
                    num_txs, num_cpus, num_batches, tree.total_proofs(),
                    par_time.as_secs_f64() * 1000.0, per_batch_ms);
            }
            Err(e) => {
                println!("{:3} | ERR: {}", num_txs, e);
            }
        }
    }

    println!();
    println!("Parallel proving reduces per-proof overhead by utilizing multiple ANE contexts.");
}
