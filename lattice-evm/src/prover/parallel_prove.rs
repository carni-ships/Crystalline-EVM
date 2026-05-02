//! Parallel Recursive Proving
//!
//! Implements parallel batch proof generation using std::thread with thread-local provers:
//! - Each thread creates its own prover (ANE context)
//! - Generate leaf proofs concurrently across threads
//! - Compose proofs sequentially using Poseidon2 Merkle tree

use crate::crypto::Poseidon2;
use crate::prover::{Prover, ProverConfig};
use std::thread;

/// Maximum elements per Labrador witness (L=4)
pub const BATCH_SIZE: usize = 4;

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

    /// Generate all leaf proofs in parallel using thread pool
    pub fn generate_leaf_proofs_parallel(&self, batches: &[Vec<u32>]) -> Result<Vec<BatchProof>, String> {
        let batch_size = batches.len();
        let num_threads = self.num_threads.min(batch_size);

        // Split batches into chunks for each thread
        let batches_per_thread = (batch_size + num_threads - 1) / num_threads;

        println!("  Using {} threads for {} batches", num_threads, batch_size);

        // Create handles for each thread
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let start = thread_id * batches_per_thread;
            let end = (start + batches_per_thread).min(batch_size);

            if start >= batch_size {
                break;
            }

            let thread_batches = batches[start..end].to_vec();
            let config = self.config.clone();

            let handle = thread::spawn(move || {
                let prover = Prover::new(config)
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

    /// Compose proofs using Poseidon2 Merkle tree
    pub fn compose_proofs(&self, proofs: &[BatchProof]) -> Result<ProofTree, String> {
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

        let prover = Prover::new(self.config.clone())
            .map_err(|e| format!("Failed to create prover: {:?}", e))?;

        let proof = prover.prove_witness(&witness)
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

    // Generate all leaf proofs in parallel
    let prove_start = std::time::Instant::now();
    let leaf_proofs = parallel_prover.generate_leaf_proofs_parallel(&batches)?;
    let leaf_time = prove_start.elapsed();

    println!("  Generated {} leaf proofs in {:?}", leaf_proofs.len(), leaf_time);

    // Compose proofs (sequential due to tree dependencies)
    let compose_start = std::time::Instant::now();
    let tree = parallel_prover.compose_proofs(&leaf_proofs)?;
    let compose_time = compose_start.elapsed();

    println!("  Composed proofs in {:?}", compose_time);

    Ok(tree)
}
