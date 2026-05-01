//! Recursive Unified Prover
//!
//! Proves full EVM execution row-by-row using recursive composition.
//! Each trace row is verified with AIR constraints.
//!
//! This is the "correct" zkEVM approach but slower than commitment-based.

use lattice_evm::prover::{Prover, ProverConfig};
use lattice_evm::evm::{execute_bytecode_with_calldata, EthClient, EthereumBlock, get_current_block_number, TraceRow};
use lattice_evm::crypto::Poseidon2;
use lattice_evm::prover::recursive_prove::{prove_full_trace_recursive, ProofTree};
use std::time::Instant;
use tracing_subscriber;

fn process_contract_recursive(
    prover: &Prover,
    addr: &str,
    code: &[u8],
    calldata: &[u8]
) -> Result<(String, ProofTree), String> {
    // Execute bytecode to get full trace
    let (_state, trace) = execute_bytecode_with_calldata(code, 1_000_000, calldata.to_vec())
        .map_err(|e| format!("{}: {}", addr, e))?;

    // Verify bytecode Merkle proofs for JUMP/JUMPI and PUSH opcodes
    let bytecode_row = TraceRow {
        pc: 0,
        opcode: 0,
        gas_before: 0,
        gas_after: 0,
        stack: vec![],
        memory: vec![],
        storage: vec![],
        call_depth: 0,
        bytecode: code.to_vec(),
        balance_before: 0,
        balance_after: 0,
        memory_ops: vec![],
        storage_ops: vec![],
        bytecode_merkle_cache: std::sync::OnceLock::new(),
    };

    let mut jump_failures = 0;
    let mut push_failures = 0;

    for row in &trace {
        // JUMP (0x56) and JUMPI (0x57)
        if row.opcode == 0x56 || row.opcode == 0x57 {
            if row.stack.len() > 0 {
                let jump_target = row.stack[row.stack.len() - 1] as usize;
                let proof = bytecode_row.compute_merkle_proof(jump_target);
                if bytecode_row.verify_merkle_proof(jump_target, &proof) {
                    if !bytecode_row.is_jumpdest(jump_target) {
                        jump_failures += 1;
                    }
                } else {
                    jump_failures += 1;
                }
            }
        }

        // PUSH1 (0x60) through PUSH32 (0x7f)
        if row.opcode >= 0x60 && row.opcode <= 0x7f {
            let push_size = (row.opcode - 0x5f) as usize;
            if row.pc >= push_size {
                let push_pos = row.pc - push_size;
                let proof = bytecode_row.compute_merkle_proof(push_pos);
                if !bytecode_row.verify_merkle_proof(push_pos, &proof) {
                    push_failures += 1;
                }
            }
        }
    }

    if jump_failures > 0 || push_failures > 0 {
        eprintln!("  {}: JUMP failures={}, PUSH failures={}", addr, jump_failures, push_failures);
    }

    // Build recursive proof tree for this contract's trace
    let tree = prove_full_trace_recursive(prover, &trace, code)
        .map_err(|e| format!("{}: {}", addr, e))?;

    let root_val = tree.root_commitment.map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).unwrap_or(0);
    println!("  {}: {} rows → {} proofs, root={:08x}",
        addr, trace.len(), tree.total_proofs(), root_val);

    Ok((addr.to_string(), tree))
}

fn main() {
    tracing_subscriber::fmt::init();

    println!("=== Recursive Unified Prover (Full ZK) ===\n");
    println!("WARNING: This proves every row. It is correct but SLOW.\n");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let block_num = match rt.block_on(get_current_block_number()) {
        Ok(n) => { println!("Current block: #{}\n", n); n }
        Err(e) => { println!("Failed: {}", e); return; }
    };

    println!("Fetching block...");
    let block = match rt.block_on(EthereumBlock::fetch(block_num)) {
        Ok(b) => b,
        Err(e) => { println!("Failed: {}", e); return; }
    };

    let hex_number = format!("0x{:x}", block_num);
    let total_txs = block.transactions.len();
    let transfers = block.transactions.iter().filter(|t| t.input.is_empty() || t.input == "0x").count();
    let contracts = total_txs - transfers;

    println!("Block #{}: {} transactions ({} transfers, {} contracts)\n",
        block_num, total_txs, transfers, contracts);

    // Collect contract bytecode with calldata
    println!("Collecting contract bytecode...");
    use std::collections::HashMap;
    use rayon::prelude::*;

    let addrs_with_calldata: Vec<(String, Vec<u8>)> = block.transactions.iter()
        .filter(|tx| !tx.input.is_empty() && tx.input != "0x")
        .filter_map(|tx| {
            let to = tx.to.as_ref()?;
            if to.is_empty() { return None; }
            let calldata = if tx.input.starts_with("0x") {
                hex::decode(&tx.input[2..]).unwrap_or_default()
            } else {
                hex::decode(&tx.input).unwrap_or_default()
            };
            Some((to.clone(), calldata))
        })
        .collect();

    let unique_addrs: Vec<String> = {
        let mut seen: HashMap<String, bool> = HashMap::new();
        addrs_with_calldata.iter()
            .filter(|(a, _)| seen.insert(a.clone(), true).is_none())
            .map(|(a, _)| a.clone())
            .collect()
    };

    println!("  Fetching {} unique contract addresses...", unique_addrs.len());

    let client = EthClient::default();

    let codes: Vec<(String, Vec<u8>, Vec<u8>)> = unique_addrs.par_iter()
        .filter_map(|addr| {
            let code = rt.block_on(client.get_code(addr, &hex_number)).ok()?;
            if code.is_empty() || code.len() >= 50000 { return None; }
            let calldata: Vec<u8> = addrs_with_calldata.iter()
                .find(|(a, _)| a == addr)
                .map(|(_, cd)| cd.clone())?;
            Some((addr.clone(), code, calldata))
        })
        .collect();

    println!("  Collected {} contracts\n", codes.len());

    // Create prover
    let prover = match Prover::new(ProverConfig::default()) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to create prover: {:?}", e);
            return;
        }
    };

    // Phase 1: Execute and prove all contracts (sequential due to global LABRADOR_OP_LOCK)
    println!("=== Phase 1: Execution + Recursive Proving ===");
    let exec_start = Instant::now();

    let mut valid_trees: Vec<(String, ProofTree)> = Vec::new();
    let mut failed: usize = 0;

    for (addr, code, calldata) in &codes {
        match process_contract_recursive(&prover, addr, code, calldata) {
            Ok((_, tree)) => valid_trees.push((addr.clone(), tree)),
            Err(e) => {
                failed += 1;
                if failed <= 3 {
                    eprintln!("Failed: {}", e);
                }
            }
        }
    }

    let exec_time_total = exec_start.elapsed().as_millis() as f64;

    println!("\nExecution + Proving complete:");
    println!("  Valid contracts: {}", valid_trees.len());
    println!("  Failed: {}", failed);
    println!("  Time: {:.0} ms", exec_time_total);

    if valid_trees.is_empty() {
        println!("No valid contracts to prove!");
        return;
    }

    // Phase 2: Count total proofs
    println!("\n=== Phase 2: Proof Statistics ===");

    let mut total_proofs = 0;
    for (_, tree) in &valid_trees {
        total_proofs += tree.total_proofs();
    }

    println!("  Total proofs: {}", total_proofs);
    println!("  Average per contract: {:.0}", total_proofs as f64 / valid_trees.len() as f64);

    // Phase 3: Compose all roots
    println!("\n=== Phase 3: Root Composition ===");
    let compose_start = Instant::now();

    let mut final_root = 0u32;
    for (_, tree) in &valid_trees {
        if let Some(root) = tree.root_commitment {
            let root_u32 = u32::from_le_bytes([root[0], root[1], root[2], root[3]]);
            final_root = Poseidon2::hash_pair(final_root, root_u32);
        }
    }

    let compose_time = compose_start.elapsed().as_millis() as f64;
    println!("  Final root: {}", final_root);
    println!("  Compose time: {:.2} ms", compose_time);

    // Summary
    let total_time = exec_time_total + compose_time;
    println!("\n=== Summary ===");
    println!("Total time: {:.0} ms ({:.2}s)", total_time, total_time / 1000.0);
    println!("  Execution + Proving: {:.0} ms ({:.1}%)", exec_time_total, (exec_time_total / total_time) * 100.0);
    println!("  Compose: {:.0} ms ({:.1}%)", compose_time, (compose_time / total_time) * 100.0);
    println!("  Total proofs generated: {}", total_proofs);
}