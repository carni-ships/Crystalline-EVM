//! Parallel Recursive Proving
//!
//! Implements parallel batch proof generation using std::thread with thread-local provers:
//! - Provers are created once and shared across threads (keygen is expensive)
//! - Generate leaf proofs concurrently across threads
//! - Compose proofs using Poseidon2 Merkle tree
//!
//! # GPU Batch Optimization
//! When GPU is available, batch proving is preferred over threading because:
//! - GPU processes ALL witnesses in parallel via Metal command queues
//! - ANE serializes all MatVec through a global lock (no true parallelism)
//! - Batch proving amortizes matrix expansion and avoids thread overhead

use crate::crypto::Poseidon2;
use crate::prover::{Prover, ProverConfig};
use orion_backend::gpu_matvec::GPUContext;
use std::thread;

/// Maximum elements per Labrador witness (L=256)
/// Larger batch size improves GPU occupancy and amortization of matrix expansion
pub const BATCH_SIZE: usize = 1024;

/// A single proof for a batch of elements
pub struct BatchProof {
    pub batch_id: usize,
    pub proof: orion_sys::LatticeZKProof,
    pub commitment: [u8; 32],
    pub elements: Vec<u32>,
}

impl std::fmt::Debug for BatchProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchProof")
            .field("batch_id", &self.batch_id)
            .field("commitment", &format!("{:02x?}", &self.commitment[..8]))
            .finish()
    }
}

impl Clone for BatchProof {
    fn clone(&self) -> Self {
        BatchProof {
            batch_id: self.batch_id,
            proof: orion_sys::LatticeZKProof {
                commitment: self.proof.commitment,
                challenge: self.proof.challenge,
                response: self.proof.response,
            },
            commitment: self.commitment,
            elements: self.elements.clone(),
        }
    }
}

/// Recursive proof aggregation tree
pub struct ProofTree {
    pub level: usize,
    pub proofs: Vec<BatchProof>,
    pub next_level: Option<Box<ProofTree>>,
    pub root_commitment: Option<[u8; 32]>,
}

impl std::fmt::Debug for ProofTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofTree")
            .field("level", &self.level)
            .field("proofs_count", &self.proofs.len())
            .field("has_next", &self.next_level.is_some())
            .finish()
    }
}

impl Clone for ProofTree {
    fn clone(&self) -> Self {
        ProofTree {
            level: self.level,
            proofs: self.proofs.clone(),
            next_level: self.next_level.as_ref().map(|b| Box::new((**b).clone())),
            root_commitment: self.root_commitment,
        }
    }
}

impl ProofTree {
    /// Get total number of proofs in tree
    pub fn total_proofs(&self) -> usize {
        let mut count = self.proofs.len();
        if let Some(ref next) = self.next_level {
            count += next.total_proofs();
        }
        count
    }
}

/// Chunk data into L=4 sized batches
pub fn chunk_data(data: &[u32]) -> Vec<Vec<u32>> {
    data.chunks(BATCH_SIZE)
        .map(|chunk| {
            let mut batch = chunk.to_vec();
            while batch.len() < BATCH_SIZE {
                batch.push(0);
            }
            batch
        })
        .collect()
}

/// Parallel proof generator using thread pool
pub struct ParallelProver {
    config: ProverConfig,
    num_threads: usize,
}

impl ParallelProver {
    pub fn new(config: ProverConfig) -> Self {
        ParallelProver {
            config,
            num_threads: 4, // Default thread count
        }
    }

    pub fn with_threads(mut self, num_threads: usize) -> Self {
        self.num_threads = num_threads;
        self
    }

    /// Generate leaf proofs using GPU batch proving (Metal compute, true parallelism)
    ///
    /// When GPU is available, this is preferred over threading because:
    /// - GPU processes ALL witnesses in parallel via Metal command queues
    /// - ANE serializes all MatVec through a global lock
    /// - Batch proving amortizes matrix expansion across all witnesses
    pub fn generate_leaf_proofs_batch_gpu(&self, batches: &[Vec<u32>]) -> Result<Vec<BatchProof>, String> {
        if batches.is_empty() {
            return Ok(Vec::new());
        }

        println!("  Using GPU batch proving for {} batches (true parallelism)", batches.len());

        // Do keygen ONCE
        let prove_start = std::time::Instant::now();
        let seed = crate::prover::generate_seed();
        let labrador_prover = orion_backend::labrador::LabradorProver::new_with_keygen(&seed);
        let pk = labrador_prover.pk;
        let vk = orion_sys::LatticeZKVerificationKey {
            q: pk.q,
            k: pk.k,
            l: pk.l,
            n: pk.n,
        };
        println!("  Keygen in {:?}", prove_start.elapsed());

        // Create prover
        let prover = Prover::new_from_keys(pk, vk)
            .map_err(|e| format!("Prover creation failed: {:?}", e))?;

        // Convert all batches to f32 witnesses
        let witnesses_f32: Vec<Vec<f32>> = batches.iter()
            .map(|batch| batch.iter().map(|&v| v as f32).collect())
            .collect();

        // Create slices from the owned Vec
        let witnesses: Vec<&[f32]> = witnesses_f32.iter().map(|v| v.as_slice()).collect();

        // GPU batch call - processes ALL witnesses in parallel
        // prove_batch() auto-selects GPU when available
        let prove_start = std::time::Instant::now();
        let proofs = prover.prove_batch(&witnesses)
            .map_err(|e| format!("Batch proving failed: {:?}", e))?;
        println!("  Batch proved {} proofs in {:?}", proofs.len(), prove_start.elapsed());

        // Build BatchProof results
        let results: Vec<BatchProof> = proofs.into_iter()
            .enumerate()
            .map(|(i, proof)| {
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&proof.commitment);
                BatchProof {
                    batch_id: i,
                    proof,
                    commitment,
                    elements: batches[i].clone(),
                }
            })
            .collect();

        Ok(results)
    }

    /// Generate all leaf proofs in parallel using thread pool
    ///
    /// Keygen is done ONCE before spawning threads (expensive ~100ms+).
    /// Each thread creates its own LatticeOps (reuses global ANE context) and
    /// LabradorProver from the pre-shared pk.
    ///
    /// When GPU is available, batch proving is preferred over threading
    /// because ANE serializes all MatVec through a global lock.
    pub fn generate_leaf_proofs_parallel(&self, batches: &[Vec<u32>]) -> Result<Vec<BatchProof>, String> {
        let batch_size = batches.len();

        // When GPU is available, prefer GPU batch proving for TRUE parallelism
        if GPUContext::available() {
            // For larger batches, GPU batch is even more beneficial
            return self.generate_leaf_proofs_batch_gpu(batches);
        }

        // For small batch counts (4 or fewer), use batch proving directly
        // This amortizes matrix expansion and avoids thread overhead
        if batch_size <= 4 {
            return self.generate_leaf_proofs_batch(batches);
        }

        let num_threads = self.num_threads.min(batch_size);
        let batches_per_thread = (batch_size + num_threads - 1) / num_threads;

        println!("  Using {} threads for {} batches", num_threads, batch_size);

        // Do keygen ONCE before spawning threads (expensive operation)
        let prove_start = std::time::Instant::now();
        let seed = crate::prover::generate_seed();
        let labrador_prover = orion_backend::labrador::LabradorProver::new_with_keygen(&seed);
        let pk = labrador_prover.pk;
        // Derive VK from the same pk
        let vk = orion_sys::LatticeZKVerificationKey {
            q: pk.q,
            k: pk.k,
            l: pk.l,
            n: pk.n,
        };
        let init_time = prove_start.elapsed();
        println!("  Keygen once in {:?}", init_time);

        // Create handles for each thread
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let start = thread_id * batches_per_thread;
            let end = (start + batches_per_thread).min(batch_size);

            if start >= batch_size {
                break;
            }

            let thread_batches = batches[start..end].to_vec();
            let pk = pk.clone(); // Clone for this thread
            let vk = vk.clone(); // Clone for this thread

            let handle = thread::spawn(move || {
                // Each thread creates its own LatticeOps (reuses global ANE singleton)
                // and LabradorProver from the pre-shared pk
                let prover = Prover::new_from_keys(pk, vk)
                    .map_err(|e| format!("Thread {} prover failed: {:?}", thread_id, e))?;

                let mut results = Vec::new();
                for (local_idx, batch) in thread_batches.iter().enumerate() {
                    let witness: Vec<f32> = batch.iter().map(|&v| v as f32).collect();
                    let proof = prover.prove_witness(&witness)
                        .map_err(|e| format!("Thread {} proof {} failed: {:?}", thread_id, local_idx, e))?;

                    let mut commitment = [0u8; 32];
                    commitment.copy_from_slice(&proof.commitment);

                    results.push(BatchProof {
                        batch_id: start + local_idx,
                        proof,
                        commitment,
                        elements: batch.clone(),
                    });
                }
                Ok(results)
            });

            handles.push(handle);
        }

        // Collect results from all threads
        let mut all_proofs = Vec::new();
        for handle in handles {
            let result = handle.join().map_err(|e| format!("Thread panicked: {:?}", e))?;
            match result {
                Ok(mut proofs) => all_proofs.append(&mut proofs),
                Err(e) => return Err(e),
            }
        }

        // Sort by batch_id
        all_proofs.sort_by_key(|p| p.batch_id);

        Ok(all_proofs)
    }

    /// Generate leaf proofs using ANE batch proving (single ANE call, no GPU)
    ///
    /// For small numbers of batches (4 or fewer), batch proving is more efficient
    /// than parallel thread-based proving because it amortizes matrix expansion
    /// and avoids thread synchronization overhead.
    pub fn generate_leaf_proofs_batch(&self, batches: &[Vec<u32>]) -> Result<Vec<BatchProof>, String> {
        if batches.is_empty() {
            return Ok(Vec::new());
        }

        println!("  Using batch proving for {} batches (amortized matrix expansion)", batches.len());

        // Do keygen ONCE
        let prove_start = std::time::Instant::now();
        let seed = crate::prover::generate_seed();
        let labrador_prover = orion_backend::labrador::LabradorProver::new_with_keygen(&seed);
        let pk = labrador_prover.pk;
        let vk = orion_sys::LatticeZKVerificationKey {
            q: pk.q,
            k: pk.k,
            l: pk.l,
            n: pk.n,
        };
        println!("  Keygen in {:?}", prove_start.elapsed());

        // Create prover
        let prover = Prover::new_from_keys(pk, vk)
            .map_err(|e| format!("Prover creation failed: {:?}", e))?;

        // Convert all batches to f32 witnesses - collect into owned Vec first
        let witnesses_f32: Vec<Vec<f32>> = batches.iter()
            .map(|batch| batch.iter().map(|&v| v as f32).collect())
            .collect();

        // Create slices from the owned Vec (these will be valid for the lifetime of witnesses_f32)
        let witnesses: Vec<&[f32]> = witnesses_f32.iter().map(|v| v.as_slice()).collect();

        // Single batch call - amortizes matrix expansion across all witnesses
        let prove_start = std::time::Instant::now();
        let proofs = prover.prove_batch(&witnesses)
            .map_err(|e| format!("Batch proving failed: {:?}", e))?;
        println!("  Batch proved {} proofs in {:?}", proofs.len(), prove_start.elapsed());

        // Build BatchProof results
        let results: Vec<BatchProof> = proofs.into_iter()
            .enumerate()
            .map(|(i, proof)| {
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&proof.commitment);
                BatchProof {
                    batch_id: i,
                    proof,
                    commitment,
                    elements: batches[i].clone(),
                }
            })
            .collect();

        Ok(results)
    }

    /// Generate leaf proofs using fused GPU kernel (MatVec + RNS + CRT on GPU)
    ///
    /// This uses the new `matvec_rns_crt` GPU kernel which computes:
    /// 1. MatVec result (A*s mod q)
    /// 2. All 5 RNS residues (for Dilithium-3: {97, 101, 103, 107, 109})
    /// 3. CRT reconstruction result
    ///
    /// This eliminates the need for ANE-based RNS decomposition.
    ///
    /// Currently falls back to GPU batch if the fused kernel isn't available.
    pub fn generate_leaf_proofs_fused(&self, batches: &[Vec<u32>]) -> Result<Vec<BatchProof>, String> {
        if batches.is_empty() {
            return Ok(Vec::new());
        }

        println!("  Using FUSED GPU kernel for {} batches (MatVec + RNS + CRT)", batches.len());

        // Do keygen ONCE
        let prove_start = std::time::Instant::now();
        let seed = crate::prover::generate_seed();
        let labrador_prover = orion_backend::labrador::LabradorProver::new_with_keygen(&seed);
        let pk = labrador_prover.pk;
        let vk = orion_sys::LatticeZKVerificationKey {
            q: pk.q,
            k: pk.k,
            l: pk.l,
            n: pk.n,
        };
        println!("  Keygen in {:?}", prove_start.elapsed());

        // Create prover
        let prover = Prover::new_from_keys(pk, vk)
            .map_err(|e| format!("Prover creation failed: {:?}", e))?;

        // Convert batches to witness format (Vec<f32>)
        let witnesses: Vec<Vec<f32>> = batches.iter()
            .map(|batch| batch.iter().map(|&v| v as f32).collect())
            .collect();

        let witness_refs: Vec<&[f32]> = witnesses.iter()
            .map(|w| w.as_slice())
            .collect();

        // Use fused GPU kernel (falls back to GPU batch if not available)
        let proofs = prover.prove_batch_fused(&witness_refs)
            .map_err(|e| format!("Fused batch prove failed: {:?}", e))?;

        // Convert to BatchProof format
        let results: Vec<BatchProof> = proofs.into_iter()
            .enumerate()
            .map(|(i, proof)| {
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&proof.commitment);
                BatchProof {
                    batch_id: i,
                    proof,
                    commitment,
                    elements: batches[i].clone(),
                }
            })
            .collect();

        Ok(results)
    }

    /// Compose proofs using Poseidon2 Merkle tree
    ///
    /// Tree building (hashing levels) is already parallel via chunks(2).map().
    /// The final root proof uses the provided prover (or creates one if None).
    pub fn compose_proofs(&self, proofs: &[BatchProof], prover: Option<&Prover>) -> Result<ProofTree, String> {
        if proofs.len() <= 1 {
            let mut tree = ProofTree {
                level: 0,
                proofs: proofs.to_vec(),
                next_level: None,
                root_commitment: proofs.first().map(|p| p.commitment),
            };
            tree.root_commitment = tree.proofs.first().map(|p| p.commitment);
            return Ok(tree);
        }

        // Build Merkle tree of proofs using Poseidon2
        // All hashes at each level are independent - already parallel via chunks().map()
        let mut current_level: Vec<u32> = proofs.iter()
            .map(|p| Poseidon2::hash_pair(p.commitment[0] as u32, p.commitment[1] as u32))
            .collect();

        let all_proofs = proofs.to_vec();
        let mut level = 0;

        while current_level.len() > 1 {
            let next_level: Vec<u32> = current_level.chunks(2)
                .map(|chunk| {
                    let a = chunk[0];
                    let b = chunk.get(1).copied().unwrap_or(a);
                    Poseidon2::hash_pair(a, b)
                })
                .collect();

            current_level = next_level;
            level += 1;
        }

        // Create final composition proof from root hash
        let root_hash = current_level[0];
        let root_bytes = root_hash.to_le_bytes();
        let witness: Vec<f32> = vec![
            root_bytes[0] as f32,
            root_bytes[1] as f32,
            root_bytes[2] as f32,
            root_bytes[3] as f32,
        ];

        // Reuse provided prover or create new one (avoid redundant keygen)
        let root_prover = if let Some(p) = prover {
            p
        } else {
            // Only create if not provided - this does keygen which is expensive
            &Prover::new(self.config.clone())
                .map_err(|e| format!("Failed to create prover: {:?}", e))?
        };

        let proof = root_prover.prove_witness(&witness)
            .map_err(|e| format!("Root proof failed: {:?}", e))?;

        let mut root_commitment = [0u8; 32];
        root_commitment.copy_from_slice(&proof.commitment);

        let tree = ProofTree {
            level,
            proofs: all_proofs,
            next_level: None,
            root_commitment: Some(root_commitment),
        };

        Ok(tree)
    }
}

impl Clone for ParallelProver {
    fn clone(&self) -> Self {
        ParallelProver {
            config: self.config.clone(),
            num_threads: self.num_threads,
        }
    }
}

/// Build proof tree with parallel leaf generation
pub fn build_proof_tree_parallel(
    config: &ProverConfig,
    trace_data: &[u32],
) -> Result<ProofTree, String> {
    println!("  Parallel proving with std::thread thread pool");

    // Chunk data into batches
    let batches = chunk_data(trace_data);
    println!("  Chunked {} elements into {} batches of {}",
        trace_data.len(), batches.len(), BATCH_SIZE);

    // Create parallel prover with configured thread count
    let num_cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    let parallel_prover = ParallelProver::new(config.clone()).with_threads(num_cpus);

    // Create ONE prover upfront that we'll reuse for composition
    // (keygen is expensive, so we do it once)
    let prove_start = std::time::Instant::now();
    let prover = Prover::new(config.clone())
        .map_err(|e| format!("Failed to create prover: {:?}", e))?;
    println!("  Created prover for composition in {:?}", prove_start.elapsed());

    // Generate all leaf proofs in parallel
    let prove_start = std::time::Instant::now();
    let leaf_proofs = parallel_prover.generate_leaf_proofs_parallel(&batches)?;
    let leaf_time = prove_start.elapsed();

    println!("  Generated {} leaf proofs in {:?}", leaf_proofs.len(), leaf_time);

    // Compose proofs (using the same prover we created above)
    let compose_start = std::time::Instant::now();
    let tree = parallel_prover.compose_proofs(&leaf_proofs, Some(&prover))?;
    let compose_time = compose_start.elapsed();

    println!("  Composed proofs in {:?}", compose_time);

    Ok(tree)
}
