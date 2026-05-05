# Performance Optimization Analysis

## Current Profiling: Where Time Is Spent

Based on analysis of `src/crypto/multilinear_pcs.rs` and `src/prover/recursive_prove.rs`:

```
Estimated time breakdown for block #25025880 (218 rows):
├── EVM tracing:              ~1ms (sequential, CPU)
├── Poseidon hashing:         ~5ms (parallel, CPU)
├── Labrador proving:          ~100ms (MatVec on ANE)
│   └── Already parallelized across 12 threads
├── Sumcheck:                ~50ms (sequential rounds, CPU)
│   ├── sum_over_first_var:   ~20ms (tree reduction)
│   ├── Merkle tree build:    ~15ms (parallel tree construction)
│   └── Poseidon challenges: ~15ms (sequential hashing)
├── NovaIVC folding:         ~10ms (sequential, field arithmetic)
└── Total:                   ~165ms
```

---

## Optimization 1: Parallel Sumcheck Rounds

### Current Sequential Implementation

```rust
// src/crypto/multilinear_pcs.rs:294-338
for round in 0..n {
    // Each round is sequential:
    let summed = current_poly.sum_over_first_var();  // Tree reduction
    let tree = MerkleTree::build(&summed);          // Tree construction
    let comm = tree.root();
    let challenge = challenges[round];
    current_poly = current_poly.partial_evaluate(var_idx, challenge);  // Depends on challenge
}
```

### Problem: Sequential Dependencies

Each round i must complete before round i+1 because:
1. Challenge for round i+1 depends on commitment from round i
2. `partial_evaluate` for round i+1 needs challenge from round i

### Opportunity: Parallelize Within Rounds

While rounds are sequential, **within each round** we can parallelize:

```rust
// BEFORE (sequential):
fn sum_over_first_var(&self) -> Vec<u32> {
    let mut result = vec![0u32; self.evaluations.len() / 2];
    for i in 0..result.len() {
        result[i] = self.evaluations[2*i] + self.evaluations[2*i+1];  // Sequential!
    }
    result
}

// AFTER (parallel using rayon):
fn sum_over_first_var_parallel(&self) -> Vec<u32> {
    use rayon::prelude::*;
    let len = self.evaluations.len() / 2;
    (0..len).into_par_iter()
        .map(|i| self.evaluations[2*i].wrapping_add(self.evaluations[2*i+1]))
        .collect()
}
```

### Proposed Changes

```rust
// In sum_over_first_var, use rayon for parallel reduction:
// Current: O(n) sequential
// Proposed: O(n/p) parallel across n/2 elements

// Similar for MerkleTree::build:
// Current: sequential tree construction
// Proposed: parallel leaf hashing, then sequential tree combine
```

### Expected Speedup

| Round Component | Current | Parallel | Speedup |
|----------------|---------|----------|---------|
| `sum_over_first_var` | 20ms | 5ms (4x parallel) | 4x |
| `MerkleTree::build` | 15ms | 4ms (4x parallel) | 4x |
| **Round total** | 35ms | 9ms | **~4x** |

### Implementation Notes

```rust
// Add parallel version to multilinear_pcs.rs:
impl MultilinearPolynomial {
    /// Parallel sum over first variable using rayon
    pub fn sum_over_first_var_parallel(&self) -> Vec<u32> {
        use rayon::prelude::*;
        let half = self.evaluations.len() / 2;
        (0..half).into_par_iter()
            .map(|i| self.evaluations[2*i].wrapping_add(self.evaluations[2*i+1]))
            .collect()
    }
}
```

---

## Optimization 2: Batch Poseidon Hashing with SIMD

### Current: Sequential Hashing

```rust
// Poseidon2 hashing - sequential per element
for elem in elements {
    hash = Poseidon2::hash_pair(hash, elem);
}
```

### Opportunity: Batch Poseidon

Poseidon2 operates on 8-element state. We can use **AVX2/NEON** for parallel S-boxes:

```rust
// AVX2: Process 8 field elements at once
// Each S-box: x^5 can be SIMD-vectorized

// NEON (Apple Silicon): Similar speedup
// Could use std::simd or portable_simd
```

### Expected Speedup

| Operation | Current | SIMD | Speedup |
|-----------|---------|-------|---------|
| Poseidon2 | 0.001ms/hash | 0.0001ms/hash | 10x |
| Total hashing | 5ms | 0.5ms | **10x** |

### Implementation Notes

```rust
// Using std::simd (Rust nightly or portable_simd crate):
use std::simd::u32x8;

fn poseidon_batch(inputs: &[u32]) -> Vec<u32> {
    // Process 8 elements at a time with SIMD
    // Each iteration: 8 S-boxes in parallel
}
```

---

## Optimization 3: SuperNeo Multifolding (Already Implemented)

### Current: Sequential NovaIVC Folding

```rust
// src/prover/recursive_prove.rs:820-860
for step in 0..n_steps {
    // Each fold depends on previous:
    let r = Poseidon2::hash_pair(running.u, step_cccs.u);
    comm_w_new = r * comm_w_old + comm_w_cccs;  // Sequential!
}
```

### SuperNeo: Fold Multiple Steps at Once

From `src/prover/recursive_prove.rs:425-430`:
```rust
pub struct SuperNovaProof {
    pub challenges: Vec<u32>,  // Precomputed challenges
    pub num_folds: usize,       // Multiple folds per round
}
```

**Already implemented!** The SuperNeoProver uses multifolding with precomputed challenges.

### Expected Speedup

| Mode | Folds per Challenge | Total Folds | Speedup |
|------|---------------------|-------------|---------|
| NovaIVC | 1 | n | 1x |
| SuperNeo | k | n/k | **~k/2** (challenges precomputed) |

---

## Optimization 4: Pipelined Batch Proving

### Current: Synchronous Batching

```rust
// In parallel_prove.rs:
for batch in batches {
    let proof = prover.prove_witness(&witness);  // Wait for each
    results.push(proof);
}
```

### Opportunity: Overlap FFI Call Latency

The ANE FFI call has ~1ms latency. We can overlap it:

```rust
// Pipeline version:
let mut results = Vec::new();
let mut in_flight: Vec<(usize, Future)> = Vec::new();

for (i, batch) in batches.iter().enumerate() {
    let witness = batch_to_witness(batch);
    // Submit without waiting
    let future = prover.prove_witness_async(&witness);  // Non-blocking
    in_flight.push((i, future));

    // Collect completed (keep 4 in flight max)
    if in_flight.len() >= 4 {
        if let Some((idx, result)) = futures::future::select_all(in_flight).await {
            results.push((idx, result));
        }
    }
}
```

### Expected Speedup

| Batches | Current | Pipelined (4-way) | Speedup |
|---------|---------|-------------------|---------|
| 18 | 18 × 7ms = 126ms | ~35ms (4x overlap) | **~4x** |

---

## Optimization 5: Precomputed Merkle Trees

### Current: Rebuild Each Time

```rust
// In sumcheck: MerkleTree::build(&summed) for each round
// This allocates and hashes repeatedly
```

### Opportunity: Reuse Computed Nodes

```rust
// Build tree once, cache intermediate nodes
struct CachedMerkleTree {
    levels: Vec<Vec<u32>>,  // All levels
    root: u32,
}

impl CachedMerkleTree {
    fn build_cached(leaves: &[u32]) -> Self {
        let mut levels = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();

        while current.len() > 1 {
            current = current.chunks(2)
                .map(|pair| Poseidon2::hash_pair(pair[0], pair[1]))
                .collect();
            levels.push(current.clone());
        }

        CachedMerkleTree { levels, root: current[0] }
    }

    // O(1) access to any node
    fn get_node(&self, depth: usize, index: usize) -> u32 {
        self.levels[depth][index]
    }
}
```

### Expected Speedup

| Operation | Current | Cached | Speedup |
|-----------|---------|--------|---------|
| Auth path | O(log n) rebuild | O(1) lookup | ~8x for n=256 |

---

## Optimization 6: Larger Witness Batching

### Current: L=256 Fixed

```rust
// src/prover/mod.rs:10
const LATTICEZK_L: usize = 256;  // Fixed by Labrador
```

### Opportunity: Multiple Batches of 256

Instead of batching at the witness level, batch **proofs**:

```rust
// Instead of: prove 256 elements, get 1 proof
// Do: prove 256×4=1024 elements, get 4 proofs, verify together

// Advantage: Reduces fixed overhead per proof
// Disadvantage: Larger intermediate representations
```

---

## Summary: Implementation Priority

| Optimization | Difficulty | Expected Speedup | Priority |
|-------------|-----------|-----------------|----------|
| Parallel sumcheck rounds | Medium | 2-3x | **HIGH** |
| Parallel Merkle tree build | Easy | 1.5-2x | **HIGH** |
| SIMD Poseidon | Hard (needs SIMD) | 2-5x | MEDIUM |
| Pipelined FFI calls | Medium | 2-4x | **HIGH** |
| SuperNeo (already done) | Done | 1.5-2x | Done |
| Cached Merkle trees | Easy | 1.5x | MEDIUM |
| Larger batching | Easy | 1.2x | LOW |

---

## Recommended First Steps

1. **Parallel sum_over_first_var** - Easy win, significant impact
2. **Parallel MerkleTree::build** - Easy, complements sumcheck
3. **Pipelined FFI calls** - Medium, significant throughput gain
4. **SIMD Poseidon** - Hard, but would help hashing bottleneck

---

## Code Locations to Modify

| Optimization | File | Function |
|-------------|------|----------|
| Parallel sum | `src/crypto/multilinear_pcs.rs` | `sum_over_first_var` |
| Parallel Merkle | `src/crypto/multilinear_pcs.rs` | `MerkleTree::build` |
| Pipeline FFI | `src/prover/parallel_prove.rs` | `generate_leaf_proofs_parallel` |
| SIMD Poseidon | `src/crypto/poseidon2.rs` | `sbox`, `apply_mds` |
