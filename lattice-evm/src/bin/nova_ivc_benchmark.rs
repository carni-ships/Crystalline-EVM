//! NovaIVC Augmented Proof Benchmark
//!
//! Tests the performance and proof size of NovaIVC with augmented CCS proof.

use lattice_evm::prover::{Prover, ProverConfig};
use lattice_evm::prover::recursive_prove::{NovaIVCProver, verify_nova_proof, NovaIVCProof, AugmentedProof, SuperNeoProver, verify_supernova_proof, SuperNovaProof};
use lattice_evm::evm::{execute_bytecode, TraceRow};
use lattice_evm::crypto::Poseidon2;
use std::time::Instant;
use bincode;

fn main() {
    println!("=== NovaIVC Augmented Proof Benchmark ===\n");

    // Try to create prover
    let prover = match Prover::new(ProverConfig::default()) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to create prover (ANE not available?): {:?}", e);
            println!("Will run basic benchmarks only (no actual proving).");
            println!();
            run_basic_benchmarks();
            return;
        }
    };

    println!("Prover initialized - ANE: {}, GPU: {}\n", prover.ane_available(), prover.gpu_available());

    // Test cases with different complexity
    let test_cases = vec![
        ("Simple ADD", vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]),
        ("Fibonacci loop", vec![
            0x60, 0x01,  // PUSH1 1
            0x60, 0x01,  // PUSH1 1
            0x5b,        // JUMPDEST
            0x60, 0x05,  // PUSH1 5
            0x56,        // JUMP
            0x5b,        // JUMPDEST
            0x60, 0x00,  // PUSH1 0
            0x00,        // STOP
            0x60, 0x01,  // PUSH1 1
            0x01,        // ADD
        ]),
        ("Storage operations", vec![
            0x60, 0x80,  // PUSH1 0x80
            0x60, 0x40,  // PUSH1 0x40
            0x54,        // SLOAD
            0x60, 0x01,  // PUSH1 1
            0x01,        // ADD
            0x60, 0x80,  // PUSH1 0x80
            0x55,        // SSTORE
            0x00,        // STOP
        ]),
        ("Multiple JUMPs", vec![
            0x5b,        // JUMPDEST
            0x60, 0x01,  // PUSH1 1
            0x60, 0x0A,  // PUSH1 10
            0x56,        // JUMP
            0x5b,        // JUMPDEST
            0x60, 0x02,  // PUSH1 2
            0x60, 0x0B,  // PUSH1 11
            0x56,        // JUMP
            0x5b,        // JUMPDEST
            0x00,        // STOP
        ]),
    ];

    println!("| Test Case | Rows | Prove Time | Proof Size | Aug Proof Size | Verify |");
    println!("|-----------|------|------------|------------|-----------------|--------|");

    for (name, code) in &test_cases {
        let trace = match execute_bytecode(code, 1000000) {
            Ok((_, t)) => t,
            Err(_) => {
                println!("| {} | ERROR executing bytecode |", name);
                continue;
            }
        };

        let trace_rows = trace.len();
        let trace_elements: usize = trace.iter()
            .map(|r| r.to_commit_prove_field_elements().len())
            .sum();

        // Benchmark NovaIVC prove (batch mode)
        let nova_prover = NovaIVCProver::new(4); // batch_size=4

        let prove_start = Instant::now();
        let proof_result = nova_prover.prove(&prover, &trace);
        let prove_time = prove_start.elapsed().as_millis() as f64;

        match proof_result {
            Ok(proof) => {
                let proof_size = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
                let aug_proof_size = proof.augmented_proof.len();

                // Verify the proof
                let verify_start = Instant::now();
                let verified = verify_nova_proof(&proof);
                let verify_time = verify_start.elapsed().as_millis() as f64;

                println!("| {} | {} | {:.2}ms | {} bytes | {} bytes | {:.3}ms ({}) |",
                    name, trace_rows, prove_time, proof_size, aug_proof_size, verify_time,
                    if verified { "PASS" } else { "FAIL" });
            }
            Err(e) => {
                println!("| {} | {} | PROVE ERROR: {:?} |", name, trace_rows, e);
            }
        }
    }

    println!();
    println!("=== Per-Opcode NovaIVC Benchmark ===\n");

    // Per-opcode proving test (individual step proofs)
    for (name, code) in &test_cases {
        let trace = match execute_bytecode(code, 1000000) {
            Ok((_, t)) => t,
            Err(_) => continue,
        };

        let trace_rows = trace.len();

        // Per-opcode mode (batch_size=1)
        let nova_prover = NovaIVCProver::new(1);

        let prove_start = Instant::now();
        let proof_result = nova_prover.prove_per_opcode(&prover, &trace);
        let prove_time = prove_start.elapsed().as_millis() as f64;

        match proof_result {
            Ok(proof) => {
                let proof_size = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
                let aug_proof_size = proof.augmented_proof.len();

                let verify_start = Instant::now();
                let verified = verify_nova_proof(&proof);
                let verify_time = verify_start.elapsed().as_millis() as f64;

                let per_op_time = prove_time / trace_rows as f64;

                println!("Per-opcode {}: {} rows, {:.2}ms total ({:.3}ms/op), proof={}bytes, aug={}bytes, verify={:.3}ms [{}]",
                    name, trace_rows, prove_time, per_op_time, proof_size, aug_proof_size, verify_time,
                    if verified { "PASS" } else { "FAIL" });
            }
            Err(e) => {
                println!("Per-opcode {}: ERROR {:?}", name, e);
            }
        }
    }

    println!();
    println!("=== Augmented Proof Analysis ===\n");

    // Analyze augmented proof size across different n values
    println!("AugmentedProof size by witness elements (n):");
    println!("| n | Aug Proof Size | SumcheckProof size |");
    println!("|---|----------------|-------------------|");

    for n in [1, 4, 16, 64, 256, 1024].iter() {
        // Create a dummy proof with specific n
        let proof = AugmentedProof::prove(*n as u32, 12345, 0, 0, *n);
        let bytes = proof.to_bytes();
        println!("| {} | {} bytes | {} bytes (sumcheck) |", n, bytes.len(), bytes.len() - 16); // 16 for header (r, n, comm_w_old, comm_w_cccs)
    }

    println!();
    println!("=== Proof Size Comparison ===\n");

    // Compare NovaIVC proof size vs. traditional approaches
    if let Ok((_, trace)) = execute_bytecode(&vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00], 1000000) {
        let nova_prover = NovaIVCProver::new(4);
        if let Ok(proof) = nova_prover.prove(&prover, &trace) {
            let nova_size = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);

            // LatticeZKProof is 96 bytes
            let lattice_proof_size = 96;
            let trace_rows = trace.len();

            println!("Traditional approach (per-row proof):");
            println!("  {} trace rows × {} bytes = {} bytes", trace_rows, lattice_proof_size, trace_rows * lattice_proof_size);
            println!();
            println!("NovaIVC (constant-sized):");
            println!("  NovaIVCProof: {} bytes", nova_size);
            println!("  Augmented proof overhead: {} bytes", proof.augmented_proof.len());
            println!();
            let compression = (trace_rows * lattice_proof_size) as f64 / nova_size as f64;
            println!("Compression ratio: {:.1}x smaller with NovaIVC", compression);
        }
    }

    println!();
    println!("=== SuperNeo vs Nova Comparison ===\n");

    // Compare SuperNeo with Nova on same test cases
    println!("| Test Case | Rows | Nova Time | SuperNeo Time | Speedup | Nova Size | SuperNeo Size |");
    println!("|-----------|------|-----------|---------------|---------|-----------|---------------|");

    for (name, code) in &test_cases {
        let trace = match execute_bytecode(code, 1000000) {
            Ok((_, t)) => t,
            Err(_) => continue,
        };

        let trace_rows = trace.len();

        // Nova per-opcode proving
        let nova_prover = NovaIVCProver::new(1);
        let nova_start = Instant::now();
        let nova_result = nova_prover.prove_per_opcode(&prover, &trace);
        let nova_time = nova_start.elapsed().as_millis() as f64;

        // SuperNeo per-opcode proving
        let superneo_prover = SuperNeoProver::new(1, trace_rows);
        let superneo_start = Instant::now();
        let superneo_result = superneo_prover.prove_per_opcode(&prover, &trace);
        let superneo_time = superneo_start.elapsed().as_millis() as f64;

        match (nova_result, superneo_result) {
            (Ok(nova_proof), Ok(supernova_proof)) => {
                let nova_size = bincode::serialize(&nova_proof).map(|b| b.len()).unwrap_or(0);
                let supernova_size = bincode::serialize(&supernova_proof).map(|b| b.len()).unwrap_or(0);
                let speedup = if superneo_time > 0.0 { nova_time / superneo_time } else { 0.0 };

                let nova_verified = verify_nova_proof(&nova_proof);
                let supernova_verified = verify_supernova_proof(&supernova_proof);

                println!("| {} | {} | {:.2}ms | {:.2}ms | {:.2}x | {} bytes | {} bytes |",
                    name, trace_rows, nova_time, superneo_time, speedup, nova_size, supernova_size);
                println!("| | | | | | Nova verify: {} | SuperNeo verify: {} |",
                    if nova_verified { "PASS" } else { "FAIL" },
                    if supernova_verified { "PASS" } else { "FAIL" });
            }
            (Err(e), _) => {
                println!("| {} | {} | ERROR (Nova): {:?} |", name, trace_rows, e);
            }
            (_, Err(e)) => {
                println!("| {} | {} | | ERROR (SuperNeo): {:?} |", name, trace_rows, e);
            }
        }
    }

    println!();
    println!("=== SuperNeo Multifolding Analysis ===\n");

    // Analyze SuperNeo with different batch sizes
    println!("SuperNeo batch_size impact on proof size:");
    println!("| Batch Size | Proof Size | Augmented Size |");
    println!("|------------|------------|----------------|");

    for batch_size in [1, 2, 4, 8].iter() {
        if let Ok((_, trace)) = execute_bytecode(&vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00], 1000000) {
            let n_steps = (trace.len() + batch_size - 1) / batch_size;
            let superneo_prover = SuperNeoProver::new(*batch_size, n_steps);
            if let Ok(proof) = superneo_prover.prove(&prover, &trace) {
                let proof_size = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
                println!("| {} | {} bytes | {} bytes |", batch_size, proof_size, proof.augmented_proof.len());
            }
        }
    }
}

fn run_basic_benchmarks() {
    println!("Running basic benchmarks (no ANE)...\n");

    let test_cases = vec![
        ("Simple", vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]),
        ("Storage", vec![0x60, 0x80, 0x60, 0x40, 0x54, 0x60, 0x01, 0x01, 0x60, 0x80, 0x55, 0x00]),
    ];

    println!("| Test Case | Trace Rows | Trace Elements |");
    println!("|-----------|------------|---------------|");

    for (name, code) in &test_cases {
        let trace = match execute_bytecode(code, 1000000) {
            Ok((_, t)) => t,
            Err(_) => continue,
        };

        let trace_rows = trace.len();
        let trace_elements: usize = trace.iter()
            .map(|r| r.to_commit_prove_field_elements().len())
            .sum();

        println!("| {} | {} | {} |", name, trace_rows, trace_elements);
    }

    println!();
    println!("AugmentedProof structure analysis:");
    println!("  - sumcheck_proof: SumcheckProof (num_vars, claims, commitments, challenges, final_evals)");
    println!("  - r: u32 (4 bytes)");
    println!("  - n: usize (8 bytes)");
    println!("  - comm_w_old: u32 (4 bytes)");
    println!("  - comm_w_cccs: u32 (4 bytes)");

    // Estimate sizes
    println!();
    println!("Estimated augmented proof sizes:");
    println!("  n=1:   ~100-200 bytes (2^1=2 evals for sumcheck)");
    println!("  n=4:   ~200-400 bytes (2^2=4 evals)");
    println!("  n=256: ~1000-2000 bytes (2^8=256 evals)");
}