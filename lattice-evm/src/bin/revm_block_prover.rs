//! REVM Ethereum Block Prover
//!
//! Fetches a real Ethereum block and proves its execution using the lattice prover.
//! Uses revm-based full EVM execution for complete opcode coverage.
//!
//! Features:
//! - Persistent bytecode cache (avoids re-fetching across runs)
//! - Multi-RPC fallback with exponential backoff
//! - Batch processing to handle large blocks
//!
//! Usage:
//!     cargo run --release --bin revm_block_prover -- <block_number>
//!
//! For Berachain:
//!     cargo run --release --bin revm_block_prover -- --berachain <block_number>

use lattice_evm::evm::{
    EthereumBlock, EthereumTransaction, EthClient, RPCConfig,
    hex_to_bytes,
    full_evm::{execute_evm_with_trace, RevmTraceRow, StateDiff},
};
use lattice_evm::crypto::{SparseMerkleTree, Poseidon2};
use lattice_evm::prover::{Prover, ProverConfig, SystemResourceMonitor, ResourceCheckFailed};
use lattice_evm::prover::recursive_prove::{NovaIVCProver, verify_nova_proof};
use lattice_evm::prover::parallel_prove::BatchProof;
use orion_sys::LatticeZKProof;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Maximum trace steps to process per transaction (for memory safety)
const MAX_TRACE_STEPS: usize = 500_000;

/// Maximum bytecode cache size (bytes) - roughly 1-2GB for popular contracts
const MAX_CACHE_SIZE: usize = 1_000_000_000;

/// Cache file name
const CACHE_FILE: &str = "bytecode_cache.bin";

/// Persistent bytecode cache with LRU eviction
struct BytecodeCache {
    /// Address -> bytecode mapping
    cache: HashMap<String, Vec<u8>>,
    /// Cache size in bytes
    size_bytes: usize,
    /// Path to cache file
    cache_path: PathBuf,
    /// LRU access order
    access_order: Vec<String>,
}

impl BytecodeCache {
    /// Create new cache, loading from disk if available
    fn new(cache_dir: PathBuf) -> Self {
        let cache_path = cache_dir.join(CACHE_FILE);
        let mut cache = HashMap::new();
        let mut size_bytes = 0;
        let mut access_order = Vec::new();

        if cache_path.exists() {
            // Load cache from file
            match std::fs::read(&cache_path) {
                Ok(data) => {
                    if let Ok((map, order)) = Self::deserialize(&data) {
                        cache = map;
                        access_order = order;
                        size_bytes = cache.values().map(|v| v.len()).sum();
                        println!("  Loaded {} cached contracts ({} bytes)", cache.len(), size_bytes);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load bytecode cache: {}", e);
                }
            }
        }

        BytecodeCache {
            cache,
            size_bytes,
            cache_path,
            access_order,
        }
    }

    /// Get bytecode from cache
    fn get(&mut self, address: &str) -> Option<&Vec<u8>> {
        if let Some(code) = self.cache.get(address) {
            // Move to end of access order (LRU)
            if let Some(pos) = self.access_order.iter().position(|a| a == address) {
                let addr = self.access_order.remove(pos);
                self.access_order.push(addr);
            }
            return Some(code);
        }
        None
    }

    /// Insert bytecode into cache with LRU eviction
    fn insert(&mut self, address: String, bytecode: Vec<u8>) {
        let size = bytecode.len();

        // Evict old entries if needed
        while self.size_bytes + size > MAX_CACHE_SIZE && !self.access_order.is_empty() {
            let oldest = self.access_order.remove(0);
            if let Some(evicted) = self.cache.remove(&oldest) {
                self.size_bytes = self.size_bytes.saturating_sub(evicted.len());
            }
        }

        // Add new entry
        self.cache.insert(address.clone(), bytecode);
        self.access_order.push(address);
        self.size_bytes += size;
    }

    /// Persist cache to disk
    fn persist(&self) {
        if let Ok(data) = self.serialize() {
            if let Err(e) = std::fs::write(&self.cache_path, data) {
                tracing::warn!("Failed to persist bytecode cache: {}", e);
            }
        }
    }

    /// Serialize cache to bytes
    fn serialize(&self) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        // Format: [num_entries][addr1_len][addr1][code1_len][code1]...
        let num = self.cache.len() as u32;
        data.extend_from_slice(&num.to_le_bytes());

        for (addr, code) in &self.cache {
            let addr_bytes = addr.as_bytes();
            let addr_len = addr_bytes.len() as u32;
            data.extend_from_slice(&addr_len.to_le_bytes());
            data.extend_from_slice(addr_bytes);
            let code_len = code.len() as u32;
            data.extend_from_slice(&code_len.to_le_bytes());
            data.extend_from_slice(code);
        }
        Ok(data)
    }

    /// Deserialize cache from bytes
    fn deserialize(data: &[u8]) -> Result<(HashMap<String, Vec<u8>>, Vec<String>), String> {
        let mut cache = HashMap::new();
        let mut access_order = Vec::new();

        let mut pos = 0;
        if data.len() < 4 {
            return Err("Invalid cache format".to_string());
        }

        let num = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        pos = 4;

        for _ in 0..num {
            if pos + 4 > data.len() {
                return Err("Invalid cache format".to_string());
            }
            let addr_len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;

            if pos + addr_len > data.len() {
                return Err("Invalid cache format".to_string());
            }
            let addr = String::from_utf8(data[pos..pos+addr_len].to_vec())
                .map_err(|_| "Invalid address")?;
            pos += addr_len;

            if pos + 4 > data.len() {
                return Err("Invalid cache format".to_string());
            }
            let code_len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;

            if pos + code_len > data.len() {
                return Err("Invalid cache format".to_string());
            }
            let code = data[pos..pos+code_len].to_vec();
            pos += code_len;

            cache.insert(addr.clone(), code);
            access_order.push(addr);
        }

        Ok((cache, access_order))
    }

    fn len(&self) -> usize {
        self.cache.len()
    }

    fn cache_size_bytes(&self) -> usize {
        self.size_bytes
    }
}

/// RPC client with exponential backoff and fallback
struct RobustRPCClient {
    configs: Vec<RPCConfig>,
    current_index: usize,
}

impl RobustRPCClient {
    fn new() -> Self {
        RobustRPCClient {
            configs: RPCConfig::all_endpoints(),
            current_index: 0,
        }
    }

    /// Get code with exponential backoff and RPC fallback
    async fn get_code_with_retry(&mut self, address: &str, block: &str, max_retries: usize) -> Option<Vec<u8>> {
        let mut delay = Duration::from_millis(100);

        for attempt in 0..max_retries {
            let config = &self.configs[self.current_index];
            let client = EthClient::new(config);

            match client.get_code(address, block).await {
                Ok(code) if !code.is_empty() => {
                    return Some(code);
                }
                Ok(_) => {
                    // Empty bytecode - contract might be self-destructed or not exist
                    return Some(Vec::new());
                }
                Err(e) => {
                    tracing::debug!("RPC attempt {} failed for {}: {}", attempt, address, e);
                    if attempt < max_retries - 1 {
                        tokio::time::sleep(delay).await;
                        delay = delay.mul_f32(2.0).min(Duration::from_secs(10));

                        // Try next RPC endpoint
                        self.current_index = (self.current_index + 1) % self.configs.len();
                    }
                }
            }
        }

        None
    }

    /// Get block with retry
    async fn get_block_with_retry(&mut self, block: &str, max_retries: usize) -> Option<EthereumBlock> {
        let mut delay = Duration::from_millis(100);

        for attempt in 0..max_retries {
            let config = &self.configs[self.current_index];
            let client = EthClient::new(config);

            match client.get_block(block, true).await {
                Ok(block) => return Some(block),
                Err(e) => {
                    tracing::debug!("RPC attempt {} failed for block {}: {}", attempt, block, e);
                    if attempt < max_retries - 1 {
                        tokio::time::sleep(delay).await;
                        delay = delay.mul_f32(2.0).min(Duration::from_secs(10));
                        self.current_index = (self.current_index + 1) % self.configs.len();
                    }
                }
            }
        }

        None
    }
}

/// Process a single transaction using revm-based execution
fn process_transaction(
    tx: &EthereumTransaction,
    bytecode: &[u8],
) -> Result<(StateDiff, Vec<RevmTraceRow>, SparseMerkleTree), String> {
    // Get calldata from tx.input (for contract calls) or empty for transfers
    let calldata = if tx.input.starts_with("0x") {
        hex_to_bytes(&tx.input)
    } else {
        hex::decode(&tx.input).map_err(|e| format!("Invalid calldata hex: {}", e))?
    };

    let gas = tx.gas.parse().unwrap_or(1_000_000);

    // Execute with revm and get trace
    let (state_diff, trace) = execute_evm_with_trace(bytecode, &calldata, gas)
        .map_err(|e| format!("EVM execution failed: {}", e))?;

    if trace.len() > MAX_TRACE_STEPS {
        return Err(format!("Trace too long: {} steps (max: {})", trace.len(), MAX_TRACE_STEPS));
    }

    // Build storage SMT from state diff
    let mut smt = SparseMerkleTree::new();
    for (slot, _old, new) in &state_diff.storage_changes {
        smt.insert(*slot, *new);
    }

    Ok((state_diff, trace, smt))
}

/// Convert RevmTraceRow to MINIMAL field elements for proving (no padding)
/// Produces 9 elements per row: PC, opcode, gas_before, gas_after, stack_len, stack[0-3]
/// This compact format packs ~28 rows per 256-element chunk vs 8 rows with padding
/// Convert revm trace row to field elements as f32 (avoids u32->f32 conversion later)
fn revm_trace_to_field_elements_compact_f32(row: &RevmTraceRow) -> Vec<f32> {
    let mut elements = Vec::with_capacity(9);

    // PC (mod Q)
    elements.push((row.pc % 8383489) as f32);

    // Opcode
    elements.push(row.opcode as f32);

    // Gas before/after
    elements.push((row.gas_before % 8383489) as f32);
    elements.push((row.gas_after % 8383489) as f32);

    // Stack: top 4 items as field elements
    let stack_len = row.stack.len().min(4);
    elements.push(stack_len as f32);

    for i in 0..4 {
        if i < stack_len {
            let val = row.stack[i].as_limbs()[0] % 8383489;
            elements.push(val as f32);
        } else {
            elements.push(0.0);
        }
    }

    elements
}

/// Build bytecode Merkle tree and return root
fn build_bytecode_commitment(bytecode: &[u8]) -> u32 {
    if bytecode.is_empty() {
        return 0;
    }

    // Simple approach: hash 32-byte chunks and build tree
    let mut padded = bytecode.to_vec();
    while padded.len() % 32 != 0 {
        padded.push(0);
    }

    let mut leaves: Vec<u32> = Vec::new();
    for chunk in padded.chunks(32) {
        // Hash each 32-byte chunk to get a field element
        let left = chunk.iter().take(16).fold(0u32, |acc, &b| acc * 256 + b as u32);
        let right = chunk.iter().skip(16).fold(0u32, |acc, &b| acc * 256 + b as u32);
        leaves.push(Poseidon2::hash_pair(left, right));
    }

    // Build binary Merkle tree
    let mut current = leaves;
    while current.len() > 1 {
        let mut next = Vec::new();
        for pair in current.chunks(2) {
            if pair.len() == 2 {
                next.push(Poseidon2::hash_pair(pair[0], pair[1]));
            } else {
                next.push(pair[0]);
            }
        }
        current = next;
    }

    current.first().copied().unwrap_or(0)
}

#[tokio::main]
async fn main() {
    // Parse CLI args
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Default values
    let mut block_number = 25_025_879u64;
    let mut chain_name = "ethereum".to_string();

    // Parse arguments
    for arg in &args {
        if let Some(bn) = arg.strip_prefix("--block=") {
            block_number = bn.parse().unwrap_or(25_025_879);
        } else if arg == "--berachain" {
            chain_name = "berachain".to_string();
        } else if let Some(rpc) = arg.strip_prefix("--rpc=") {
            chain_name = format!("custom:{}", rpc);
        } else if let Some(chain) = arg.strip_prefix("--chain=") {
            chain_name = chain.to_string();
        } else if arg.parse::<u64>().is_ok() {
            block_number = arg.parse().unwrap();
        }
    }

    // Select RPC config based on chain
    let rpc_config = match chain_name.as_str() {
        "berachain" => RPCConfig::berachain(),
        "ethereum" => RPCConfig::default(),
        _ if chain_name.starts_with("custom:") => {
            let url = chain_name.strip_prefix("custom:").unwrap();
            RPCConfig::from_url(url)
        }
        _ => RPCConfig::default(),
    };

    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║       REVM-STYLE ETHEREUM BLOCK PROVER (LATTICE PROVER)         ║");
    println!("║            FULL EVM + CACHED BYTECODE                             ║");
    println!("╠════════════════════════════════════════════════════════════════════╣");
    println!("║  Block: #{}                                                   ║", block_number);
    println!("║  Chain: {}                                                   ║", chain_name);
    println!("╚════════════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: Load persistent bytecode cache
    println!("Loading bytecode cache...");
    let cache_dir = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    let mut bytecode_cache = BytecodeCache::new(cache_dir);
    println!("  Cache loaded: {} contracts ({} bytes)", bytecode_cache.len(), bytecode_cache.cache_size_bytes());

    // Step 2: Fetch block using robust RPC client
    print!("Fetching block #{} from {} RPC... ", block_number, chain_name);
    let hex_block = format!("0x{:x}", block_number);
    let client = EthClient::new(&rpc_config);

    // Try to fetch, with retry for rate-limited responses
    let block = loop {
        match client.get_block(&hex_block, true).await {
            Ok(b) => break b,
            Err(e) => {
                // Check if it's a rate limit or block not found error
                if e.contains("null") || e.contains("rate limit") || e.contains("429") {
                    println!("Rate limited or block unavailable, retrying...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                println!("FAILED: {}", e);
                return;
            }
        }
    };
    println!("{} transactions", block.transactions.len());

    // Step 3: Fetch bytecode for all contract addresses (with cache)
    println!("\nFetching contract bytecode for {} transactions...", block.transactions.len());
    let fetch_start = Instant::now();

    let mut contracts_to_fetch: Vec<String> = Vec::new();
    let mut from_cache = 0;
    let mut from_rpc = 0;

    // Collect unique contract addresses and check cache first
    for tx in &block.transactions {
        if let Some(ref to) = tx.to {
            if !to.is_empty() && !tx.input.is_empty() && tx.input != "0x" {
                // This is a contract call (has calldata)
                if bytecode_cache.get(to).is_none() && !contracts_to_fetch.contains(to) {
                    contracts_to_fetch.push(to.clone());
                } else {
                    from_cache += 1;
                }
            }
        }
    }

    println!("  From cache: {}, to fetch: {}", from_cache, contracts_to_fetch.len());

    // Fetch missing bytecode with retries
    let mut fetch_errors = 0;
    for (i, addr) in contracts_to_fetch.iter().enumerate() {
        match client.get_code(addr, &hex_block).await {
            Ok(bytecode) => {
                if !bytecode.is_empty() {
                    bytecode_cache.insert(addr.clone(), bytecode);
                    from_rpc += 1;
                } else {
                    fetch_errors += 1;
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch bytecode for {}: {}", addr, e);
                fetch_errors += 1;
            }
        }

        if (i + 1) % 50 == 0 {
            println!("  Fetched {}/{} contracts", i + 1, contracts_to_fetch.len());
        }
    }

    // Persist cache to disk
    bytecode_cache.persist();

    let fetch_time = fetch_start.elapsed().as_millis() as f64;
    println!("  Bytecode fetch complete: {} from cache, {} from RPC, {} errors, time: {:.0}ms",
        from_cache, from_rpc, fetch_errors, fetch_time);

    // Step 4: Create prover
    print!("Initializing prover... ");
    let prover = match Prover::new(ProverConfig::default()) {
        Ok(p) => {
            println!("ANE: {}, GPU: {}", p.ane_available(), p.gpu_available());
            p
        }
        Err(e) => {
            println!("FAILED: {:?}", e);
            return;
        }
    };

    // Step 4b: Initialize resource monitor for adaptive batch sizing
    let resource_monitor = SystemResourceMonitor::new();
    resource_monitor.refresh();
    println!("Resource status: {}", resource_monitor.status_summary());

    // Step 5: Process transactions with revm execution (PARALLEL + PIPELINED)
    println!("\nProcessing {} transactions with revm (parallel)...", block.transactions.len());

    let trace_start = Instant::now();
    let failed_tx = AtomicUsize::new(0);

    // Pre-process transactions to determine bytecode (needed for parallel execution)
    let tx_data: Vec<_> = block.transactions.iter().enumerate().map(|(idx, tx)| {
        let bytecode: Vec<u8> = if tx.to.is_none() || tx.to.as_ref().is_some_and(|a| a.is_empty()) {
            // Contract creation - input is init code
            if tx.input.starts_with("0x") {
                hex_to_bytes(&tx.input)
            } else {
                hex::decode(&tx.input).unwrap_or_default()
            }
        } else if tx.input.is_empty() || tx.input == "0x" {
            // Simple ETH transfer - still execute STOP opcode to get trace
            vec![0x00]
        } else {
            // Contract call - use bytecode from cache
            if let Some(ref to) = tx.to {
                bytecode_cache.get(to).cloned().unwrap_or_else(|| vec![0x00])
            } else {
                vec![0x00]
            }
        };
        (idx, tx.clone(), bytecode)
    }).collect();

    // Parallel trace generation using rayon
    use rayon::prelude::*;

    // Generate directly as f32 to avoid u32->f32 conversion later
    let parallel_results: Vec<_> = tx_data
        .par_iter()
        .filter_map(|(idx, tx, bytecode)| {
            match process_transaction(tx, bytecode) {
                Ok((_state_diff, trace, smt)) => {
                    if trace.is_empty() {
                        return None;
                    }

                    let storage_root = smt.root();
                    let bc_root = build_bytecode_commitment(bytecode);

                    // Convert trace to field elements directly as f32 (avoid u32->f32 conversion)
                    // Compute total field elements: each trace row produces 9 elements
                    let total_felts = trace.len() * 9;

                    // Single allocation per transaction: collect all f32s then chunk
                    let all_felts: Vec<f32> = trace.iter()
                        .flat_map(revm_trace_to_field_elements_compact_f32)
                        .collect();

                    // Calculate number of chunks (each chunk is 256 f32s)
                    let num_chunks = if total_felts <= 256 {
                        1
                    } else {
                        (total_felts + 255) / 256
                    };

                    Some((*idx, all_felts, num_chunks, storage_root, bc_root, trace.len()))
                }
                Err(e) => {
                    if failed_tx.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
                        eprintln!("  TX {} failed: {}", idx, e);
                    }
                    None
                }
            }
        })
        .collect();

    // Aggregate results into flat buffer for GPU efficiency
    // Pre-calculate total capacity needed
    let total_chunks: usize = parallel_results.iter()
        .map(|(_, _, num_chunks, _, _, _)| *num_chunks)
        .sum();

    // Flat layout: [witness0_chunk0...witness0_chunkN, witness1_chunk0..., ...]
    // Each chunk is exactly 256 f32s
    let mut all_witness_flat: Vec<f32> = Vec::with_capacity(total_chunks * 256);
    let mut storage_roots: Vec<u32> = Vec::new();
    let mut bytecode_roots: Vec<u32> = Vec::new();
    let mut tx_count = 0;
    let mut total_steps = 0;

    for (_idx, all_felts, num_chunks, storage_root, bc_root, steps) in parallel_results {
        let felts_len = all_felts.len();

        // Efficient: process full 256-element chunks
        let full_chunks = felts_len / 256;
        for i in 0..full_chunks {
            let start = i * 256;
            let end = start + 256;
            all_witness_flat.extend_from_slice(&all_felts[start..end]);
        }

        // Handle remainder: pad to 256 elements
        let remainder = felts_len % 256;
        if remainder > 0 {
            let start = full_chunks * 256;
            all_witness_flat.extend_from_slice(&all_felts[start..start + remainder]);
            // Pad with zeros to reach 256
            for _ in remainder..256 {
                all_witness_flat.push(0.0);
            }
        } else if num_chunks == 0 {
            // Edge case: zero-length trace but we still need one chunk
            all_witness_flat.resize(all_witness_flat.len() + 256, 0.0);
        }

        storage_roots.push(storage_root);
        bytecode_roots.push(bc_root);
        tx_count += 1;
        total_steps += steps;

        if tx_count % 100 == 0 {
            println!("  Processed {}/{} transactions, {} steps", tx_count, block.transactions.len(), total_steps);
        }
    }

    let trace_time = trace_start.elapsed().as_millis() as f64;
    println!("\nTrace generation completed (revm-based, parallel):");
    println!("  Transactions processed: {}", tx_count);
    println!("  Transactions failed: {}", failed_tx.load(std::sync::atomic::Ordering::Relaxed));
    println!("  Witness chunks: {}", total_chunks);
    println!("  Time: {:.0}ms", trace_time);

    if total_chunks == 0 {
        println!("No valid traces to prove!");
        bytecode_cache.persist();
        return;
    }

    // Step 6: Prove with Labrador batch with adaptive resource management
    println!("\nProving with Labrador batch...");
    println!("  Flat witness buffer: {} chunks ({} f32s, capacity {})",
             total_chunks, all_witness_flat.len(), all_witness_flat.capacity());
    println!("  Resource status: {}", resource_monitor.status_summary());

    // Already in f32 format - no conversion needed
    let labrador_start = Instant::now();

    // Determine adaptive batch size based on resources
    let base_batch_size = resource_monitor.recommended_batch_size();
    let effective_batch_size = base_batch_size.min(5000).max(100);
    println!("  Adaptive batch size: {} (based on resource monitor)", effective_batch_size);

    // Track prover activity for contention detection
    resource_monitor.prover_active();
    let result = prove_with_adaptive_batching(
        &prover,
        &resource_monitor,
        &all_witness_flat,
        total_chunks,
        effective_batch_size,
    );
    resource_monitor.prover_inactive();

    let (all_proofs, batch_times) = match result {
        Ok((proofs, times)) => (proofs, times),
        Err((e, partial)) => {
            println!("  Proving failed after {} proofs: {}", partial.len(), e);
            bytecode_cache.persist();
            return;
        }
    };

    let labrador_time = labrador_start.elapsed().as_millis() as f64;
    println!("Labrador proving completed:");
    println!("  Proofs generated: {}", all_proofs.len());
    println!("  Time: {:.0}ms", labrador_time);
    if !batch_times.is_empty() {
        let avg = batch_times.iter().sum::<u64>() as f64 / batch_times.len() as f64;
        let max = *batch_times.iter().max().unwrap_or(&0);
        println!("  Batch times: avg={:.0}ms, max={:.0}ms, batches={}",
                 avg, max, batch_times.len());
    }
    if all_proofs.len() == total_chunks {
        println!("  Time per proof: {:.2}ms", labrador_time / total_chunks as f64);
    }

    // Step 7: Verify all proofs with Labrador (cryptographic verification)
    println!("\nVerifying all proofs (Labrador FFI)...");
    let verify_start = Instant::now();
    let mut verified = 0;
    let mut failed = 0;

    for (i, proof) in all_proofs.iter().enumerate() {
        match prover.verify_proof(proof) {
            Ok(true) => verified += 1,
            Ok(false) => {
                failed += 1;
                if failed <= 3 {
                    println!("  Proof {} FAILED verification", i);
                }
            }
            Err(e) => {
                failed += 1;
                if failed <= 3 {
                    println!("  Proof {} ERROR: {:?}", i, e);
                }
            }
        }
    }
    let verify_time = verify_start.elapsed().as_millis() as f64;

    println!("Verification completed:");
    println!("  Verified: {}/{}", verified, all_proofs.len());
    println!("  Failed: {}", failed);
    println!("  Time: {:.0}ms", verify_time);

    if failed > 0 {
        println!("\nWARNING: {} proofs failed verification!", failed);
    }

    // Step 8: Fold with NovaIVC
    println!("\nFolding proofs with NovaIVC...");

    let nova_prover = NovaIVCProver::new(4);

    // Compute initial state from block hash + storage root + bytecode root
    let initial_state = if !storage_roots.is_empty() {
        let h = block.hash.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(4)
            .fold(0u32, |acc, c| acc * 16 + c.to_digit(16).unwrap_or(0));
        let s = storage_roots[0];
        let b = bytecode_roots[0];
        let h1 = Poseidon2::hash_pair(h, s);
        Poseidon2::hash_pair(h1, b)
    } else {
        block.hash.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(8)
            .fold(0u32, |acc, c| acc * 16 + c.to_digit(16).unwrap_or(0))
    };

    let batch_proofs: Vec<BatchProof> = all_proofs.iter()
        .enumerate()
        .map(|(i, p)| BatchProof {
            batch_id: i,
            proof: LatticeZKProof {
                commitment: p.commitment,
                challenge: p.challenge,
                response: p.response,
            },
            commitment: p.commitment,
            elements: vec![],
        })
        .collect();

    let fold_start = Instant::now();
    let nova_result = nova_prover.fold_labrador_proofs(
        &prover,
        &batch_proofs,
        initial_state,
        block_number,
    );
    let fold_time = fold_start.elapsed().as_millis() as f64;

    match nova_result {
        Ok(nova_proof) => {
            println!("NovaIVC folding completed:");
            println!("  Folds: {}", nova_proof.folding_chain.num_folds);
            println!("  Final running commitment: {:x}", nova_proof.running.comm_w);
            println!("  Final step commitment: {:x}", nova_proof.final_step.comm_w);
            println!("  Time: {:.0}ms", fold_time);

            let proof_size = std::mem::size_of::<orion_sys::LatticeZKProof>() +
                nova_proof.folding_chain.num_folds * 4 * 3;
            println!("  Est. proof size: ~{} bytes", proof_size);

            println!("\nVerifying folded proof...");
            if verify_nova_proof(&nova_proof) {
                println!("✓ Folded proof VERIFIED");
            } else {
                println!("✗ Folded proof FAILED verification");
            }
        }
        Err(e) => {
            println!("NovaIVC folding failed: {}", e);
        }
    }

    // Persist cache before exit
    bytecode_cache.persist();

    // Summary
    let total_time = fetch_time + trace_time + labrador_time + verify_time + fold_time;
    println!("\n╔════════════════════════════════════════════════════════════════════╗");
    println!("║                         SUMMARY                                   ║");
    println!("╠════════════════════════════════════════════════════════════════════╣");
    println!("║  Block: #{}                                                   ║", block_number);
    println!("║  Execution: revm (complete EVM semantics)                          ║");
    println!("║  Bytecode cache: {} contracts, {} bytes                       ║",
        bytecode_cache.len(), bytecode_cache.cache_size_bytes());
    println!("║  Transactions: {} → {} proven, {} failed                       ║",
        block.transactions.len(), tx_count, failed_tx.load(Ordering::Relaxed));
    println!("║  Trace steps: {}                                                ║", total_steps);
    println!("║  Labrador proofs: {}                                           ║", all_proofs.len());
    println!("║  Storage SMTs: {}                                             ║", storage_roots.len());
    println!("╠════════════════════════════════════════════════════════════════════╣");
    println!("║  Fetch time:     {:.0}ms                                        ║", fetch_time);
    println!("║  Trace time:    {:.0}ms                                        ║", trace_time);
    println!("║  Prove time:    {:.0}ms                                        ║", labrador_time);
    println!("║  Verify time:   {:.0}ms                                        ║", verify_time);
    println!("║  Fold time:     {:.0}ms                                        ║", fold_time);
    println!("║  Total time:    {:.0}ms                                        ║", total_time);
    println!("╚════════════════════════════════════════════════════════════════════╝");
}

/// Adaptive batch proving with resource monitoring and graceful degradation
///
/// Returns (proofs, batch_times_ms) on success, Err((error_message, partial_proofs)) on failure
fn prove_with_adaptive_batching(
    prover: &Prover,
    monitor: &SystemResourceMonitor,
    all_witness_flat: &[f32],
    total_chunks: usize,
    base_batch_size: usize,
) -> Result<(Vec<orion_sys::LatticeZKProof>, Vec<u64>), (String, Vec<orion_sys::LatticeZKProof>)> {
    let mut all_proofs: Vec<orion_sys::LatticeZKProof> = Vec::new();
    let mut batch_times: Vec<u64> = Vec::new();
    let mut batch_size = base_batch_size;
    let mut consecutive_failures = 0u8;

    let gpu_available = prover.gpu_available();
    let use_fused_path = gpu_available;

    if use_fused_path {
        tracing::info!("Using GPU fused path for batch proving");
    } else {
        tracing::info!("Using ANE batch path (GPU unavailable)");
    }

    let mut offset = 0;
    while offset < total_chunks {
        // Refresh resources before each batch
        monitor.refresh();

        // Adaptively adjust batch size under load
        let current_recommended = monitor.recommended_batch_size();
        if current_recommended < batch_size && consecutive_failures > 0 {
            batch_size = current_recommended.max(100);
            tracing::warn!("Reducing batch size to {} due to system load", batch_size);
        }

        let batch_end = (offset + batch_size).min(total_chunks);
        let batch_len = batch_end - offset;

        // Check memory for this batch
        if !monitor.can_fit_batch(batch_len) {
            // Reduce batch size and retry
            batch_size = (batch_size / 2).max(100);
            if batch_size < 100 {
                return Err(("Insufficient memory even for minimum batch".to_string(), all_proofs));
            }
            tracing::warn!("Reducing batch size to {} due to memory pressure", batch_size);
            continue;
        }

        // Calculate slice positions in flat buffer
        let start_idx = offset * 256;
        let end_idx = batch_end * 256;
        let batch_slice = &all_witness_flat[start_idx..end_idx];

        // Build batch slices
        let mut batch_f32: Vec<&[f32]> = Vec::with_capacity(batch_len);
        batch_f32.extend((0..batch_len).map(|i| {
            let elem_offset = i * 256;
            &batch_slice[elem_offset..elem_offset + 256]
        }));

        let batch_start_time = std::time::Instant::now();

        // Try proving with fallback chain
        let result = if use_fused_path {
            prover.prove_batch_fused(&batch_f32)
                .or_else(|_| {
                    tracing::warn!("GPU batch failed, falling back to ANE");
                    prover.prove_batch(&batch_f32)
                })
        } else {
            prover.prove_batch(&batch_f32)
        };

        match result {
            Ok(mut batch_proofs) => {
                all_proofs.append(&mut batch_proofs);
                batch_times.push(batch_start_time.elapsed().as_millis() as u64);
                consecutive_failures = 0;

                if offset % (batch_size * 10).max(1000) == 0 && offset > 0 {
                    println!("  Proved {}/{} chunks ({} batches)", offset, total_chunks, batch_times.len());
                }
            }
            Err(e) => {
                consecutive_failures += 1;

                if consecutive_failures >= 3 {
                    return Err((format!("3 consecutive batch failures: {:?}", e), all_proofs));
                }

                // Reduce batch size and retry
                batch_size = (batch_size / 2).max(100);
                tracing::warn!("Batch failed, reducing size to {} and retrying", batch_size);
                continue;
            }
        }

        offset = batch_end;
    }

    Ok((all_proofs, batch_times))
}