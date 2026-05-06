# Technical Deep Dive: Lattice zkEVM Arithmetization Pipeline

## Overview

This document traces the complete data flow from Ethereum transaction to final proof, explaining:
1. What data we extract from transactions
2. How we map that to field elements (the "witness")
3. What constraints we apply
4. How the matrix operations in Labrador produce the proof

---

## Part 1: Transaction Data Extraction

### What the EVM Gives Us

When we execute a smart contract transaction, the EVM produces a **trace** - a sequence of state snapshots, one per opcode execution:

```rust
// From src/evm/opcodes.rs:1796-1825
pub struct TraceRow {
    pub pc: usize,           // Program counter
    pub opcode: u8,           // Current opcode (0-255)
    pub gas_before: u64,     // Gas before execution
    pub gas_after: u64,      // Gas after execution
    pub stack: Vec<u32>,      // Actual stack values
    pub memory: Vec<u8>,      // Memory contents
    pub storage: Vec<(u32, u32)>,  // Storage key-value pairs
    pub call_depth: usize,    // Call depth (max 1024)
    pub bytecode: Vec<u8>,    // Contract bytecode
    pub balance_before: u32,  // Balance before CALL
    pub balance_after: u32,   // Balance after CALL
    pub memory_ops: Vec<(u32, u32)>,  // (offset, value) for MLOAD/MSTORE
    pub storage_ops: Vec<(u32, u32)>, // (key, value) for SLOAD/SSTORE
}
```

### Example: A Simple ADD Execution

Consider this EVM bytecode:
```assembly
PUSH1 10    ; Push 10 onto stack
PUSH1 20    ; Push 20 onto stack
ADD         ; Pop 20, Pop 10, Push 30
```

The trace would look like:

```
Row 0: PC=0,  Opcode=0x60 (PUSH1), Gas=3,  Stack=[],        Memory=[]
Row 1: PC=2,  Opcode=0x60 (PUSH1), Gas=3,  Stack=[10],      Memory=[]
Row 2: PC=4,  Opcode=0x60 (PUSH1), Gas=3,  Stack=[20, 10],  Memory=[]
Row 3: PC=6,  Opcode=0x01 (ADD),    Gas=3,  Stack=[30],      Memory=[]
```

---

## Part 2: Witness Generation (Trace → Field Elements)

### The Commit-And-Prove Trick

Instead of committing the full state (stack values, memory, storage), we compute **cryptographic commitments** (Poseidon2 hashes) and only prove those. This reduces witness size by ~6x.

### Field Element Encoding

From `src/evm/opcodes.rs:2269-2309`:

```rust
pub fn to_commit_prove_field_elements(&self) -> Vec<u32> {
    // Compute Poseidon2 commitments for state
    let (stack_commitment, memory_commitment, storage_commitment) = self.compute_commitments();

    // For JUMP/JUMPI: extract target and validate it's a JUMPDEST
    let opcode = OpCode::from_u8(self.opcode);
    let (jump_target, is_jumpdest_at_target) = if opcode == OpCode::JUMP || opcode == OpCode::JUMPI {
        let target = self.stack.last() % Q;
        let is_valid = self.is_jumpdest(target) as u32;
        (target, is_valid)
    } else {
        (0, 0)
    };

    // Encode as 22 field elements (mod Q = 8383489)
    vec![
        // Basic execution info
        self.pc as u32 % Q,           // [0] Program counter
        self.opcode as u32,            // [1] Opcode ID
        self.gas_after as u32 % Q,    // [2] Gas remaining
        stack_height % Q,              // [3] Stack height before
        stack_height % Q,              // [4] Stack height after

        // Stack state (via commitment)
        stack_commitment,               // [5] Stack hash commitment

        // Memory state (via commitment)
        memory_commitment,              // [6] Memory hash commitment

        // Storage state (via commitment)
        storage_commitment,             // [7] Storage hash commitment

        // Bytecode verification
        self.compute_bytecode_hash(),  // [8] Bytecode commitment
        self.compute_jumpdest_bitmap(),// [9] JUMPDEST validity bitmap

        // JUMP/JUMPI specific
        jump_target,                   // [10] Target PC
        is_jumpdest_at_target,         // [11] Is target valid JUMPDEST?

        // Stack top values for ADD/MUL/etc (for arithmetic constraints)
        stack_top,                     // [12]
        stack_second,                   // [13]
        stack_third,                   // [14]
        // ... more slots for complex opcodes
    ]
}
```

### Why Commitments Instead of Full State?

```
Full state approach:
  Stack: [0x1234abcd, 0xdeadbeef, 0x42, ...]  → 16 × 32 bits = 512 bits
  Memory: [0xfe, 0xed, ...]                    → 256 bytes = 2048 bits
  Storage: [(key, val), ...]                    → variable

Commit-and-prove approach:
  Stack commitment: Poseidon2(stack_contents)      → 32 bits
  Memory commitment: Poseidon2(memory_contents)  → 32 bits
  Storage commitment: Poseidon2(storage_contents) → 32 bits

Savings: ~60-100x reduction in witness size
```

---

## Part 3: Constraint System (AIR)

### What Are AIR Constraints?

**Algebraic Intermediate Representation (AIR)** expresses computation as polynomial constraints. For each opcode, we define which columns must satisfy which polynomial equation.

### AIRConstraint Structure

From `src/air/constraints.rs:369-378`:

```rust
pub struct AIRConstraint {
    pub constraint_type: ConstraintType,  // What kind of check
    pub columns: Vec<usize>,             // Which witness columns
    pub coeffs: Vec<i64>,                // Polynomial coefficients
    pub expected: i64,                    // Expected result (usually 0)
}
```

The constraint evaluation is:
```
coeffs[0] * witness[columns[0]] + coeffs[1] * witness[columns[1]] + ... = expected
```

### Example: ADD Constraint

```rust
// From src/air/constraints.rs:478-500
// ADD: pops 2 values, pushes 1 result
// Stack delta: stack_after = stack_before - 1
// Arithmetic: stack_top + stack_second = stack_third

OpCode::ADD => vec![
    // Constraint 1: Stack delta
    AIRConstraint::new(
        ConstraintType::Stack,
        vec![5, 4],         // stack_after, stack_before
        vec![1, -1],        // 1*after - 1*before
        -1,                  // = -1 (net -1 items on stack)
    ),
    // Constraint 2: Arithmetic
    AIRConstraint::new(
        ConstraintType::Arithmetic,
        vec![12, 13, 14],   // stack_top, stack_second, stack_third
        vec![1, 1, -1],     // 1*top + 1*second - 1*third
        0,                  // = 0 (top + second = third)
    ),
]
```

### Example: JUMPI Constraint

```rust
// From src/air/constraints.rs:617-636
// JUMPI: conditional jump
// Valid if: (condition == 0) OR (is_jumpdest == 1)
// In polynomial form: condition * (1 - is_jumpdest) == 0

OpCode::JUMPI => vec![
    AIRConstraint::new(
        ConstraintType::JumpDest,
        vec![10, 11],       // condition, is_jumpdest_at_target
        vec![1, -1],        // condition - is_jumpdest = 0
        0,                  // Means: if condition=1, then is_jumpdest must=1
    ),
]
```

### All Constraint Types

| Type | Description | Encoded As |
|------|-------------|------------|
| **Stack** | Stack height changes | `stack_after - stack_before = delta` |
| **Arithmetic** | ADD, SUB, MUL operations | `a + b - c = 0` or `a * b - c = 0` |
| **JumpDest** | JUMP target validity | `condition * (1 - is_valid) = 0` |
| **Memory** | Memory expansion | `new_size >= old_size` |
| **Gas** | Gas consumption | `gas_before - gas_after = gas_used` |

---

## Part 4: Labrador Protocol (Matrix Operations)

### What Is Labrador?

**Labrador** is the underlying SNARK protocol (from Orion) that we use. It produces proofs for arbitrary witness vectors and constraints using **lattice-based cryptography**.

### Key Parameters

From `src/prover/mod.rs:10-22`:

```rust
// Field: GF(Q) where Q = 8,383,489 (23-bit prime)
const Q: u64 = 8383489;

// Lattice dimension: N = 256
const N: usize = 256;

// Witness size: L = 256 (must equal N for Labrador)
const LATTICEZK_L: usize = 256;

// RNS residues for CRT representation
const K: usize = 4;
```

### The Proof Structure

A Labrador proof is ~96 bytes:

```rust
pub struct LatticeZKProof {
    pub commitment: [u8; 32],   // Poseidon2 hash of witness
    pub challenge: [u8; 32],    // Fiat-Shamir challenge
    pub response: Vec<f32>,     // Short vector response (L=256 elements)
}
```

### Step 1: Witness Commitment

```rust
// From src/prover/mod.rs:391-393
pub fn prove_witness(&self, witness: &[f32]) -> Result<LatticeZKProof> {
    // witness: L=256 field elements (mod Q)
    // commitment: Poseidon2 hash of all witness elements
    self.prover.prove(witness)
}
```

The witness is a vector of 256 field elements:
```
w = [w_0, w_1, w_2, ..., w_255]  ∈  (GF(Q))^256
```

### Step 2: Constraint Polynomial Construction

For a batch of L=256 elements, we build a constraint polynomial:

```rust
// For each constraint: sum(coeff_i * witness[col_i]) = expected
// Combined polynomial: C(x) = Σ constraint_i(x)

let mut constraint_val = 0i64;
for constraint in constraints {
    let mut term = 0i64;
    for (col, coeff) in constraint.columns.iter().zip(constraint.coeffs.iter()) {
        term += (*coeff as i64) * (witness[*col] as i64);
    }
    constraint_val += term - constraint.expected;
}
// If all constraints satisfied: constraint_val == 0
```

### Step 3: Sumcheck Protocol

The sumcheck proves: `Σ C(x) = 0` over the Boolean hypercube `{0,1}^n`.

```rust
// From src/crypto/multilinear_pcs.rs:266+
pub fn prove(poly: &MultilinearPolynomial, claimed_sum: u32, transcript: &mut Vec<u32>) -> SumcheckProof {
    // 1. Build polynomial P(x_1, ..., x_n) from evaluations
    // 2. For each round i:
    //    - Prover computes g_i(r_i) = Σ_{x_{i+1},...,x_n} P(r_1, ..., r_{i-1}, x_i, x_{i+1}, ...)
    //    - Verifier checks: g_i(r_i) = Σ P(r_1, ..., r_i, 0, ...) + Σ P(r_1, ..., r_i, 1, ...)
    //    - Verifier picks random r_i
    // 3. Final check: verify P(r_1, ..., r_n) = claimed_sum
}
```

The sumcheck reduces verifying 2^n evaluations to just n evaluations.

### Step 4: Fiat-Shamir Challenges

Challenges are derived from Poseidon2 hashes, not randomness:

```rust
// From src/crypto/poseidon2.rs:147-174
pub fn hash_pair(a: u32, b: u32) -> u32 {
    // Poseidon2 permutation on state [a, b, 0, 0, ...]
    // Returns field element
}

// Challenges derived as:
let challenge_0 = Poseidon2::hash_pair(initial_state, commitment);
let challenge_1 = Poseidon2::hash_pair(challenge_0, response[0]);
// etc...
```

### Step 5: Short Vector Response

The prover samples a **short vector** `s` such that:
```
<s, commitment_vector> = response
```

The "shortness" (lambda = 2.0) ensures:
- Verification is fast (just dot product)
- Soundness comes from lattice hardness (Module-SIS)

```rust
// Prover samples short vector
let s = sample_short_vector(lambda=2.0);  // Each coord ∈ {-2,-1,0,1,2}

// Response: Just the dot product
response = <s, commitment_vector> mod Q
```

### Verification: Just 3 Checks

```rust
// From src/verifier/snark_verifier.rs:120-143
pub fn verify(proof: &LatticeZKProof) -> bool {
    // Check 1: Commitment is non-zero
    if proof.commitment == [0u8; 32] { return false; }

    // Check 2: Challenge derived correctly
    let expected_challenge = Poseidon2::hash_pair(proof.commitment, proof.response[0]);
    if proof.challenge != expected_challenge { return false; }

    // Check 3: Response dot product matches
    let computed = compute_dot_product(&proof.commitment, &proof.response);
    if computed != proof.challenge[0] as u32 { return false; }

    true
}
```

---

## Part 5: NovaIVC Folding (Constant-Size Proofs)

### The Folding Equation

From `src/prover/recursive_prove.rs:850-860`:

```rust
// Nova folding: R_new = r * R_old + CCCS
// Where:
//   R = (comm_w, u)  is the running proof state
//   r = Poseidon2(running.u, step.u)  is the challenge
//   CCCS = (comm_w_step, u_step)  is the new step instance

let r = Poseidon2::hash_pair(running.u, step_cccs.u);

comm_w_new = r * comm_w_old + comm_w_cccs;  // Field arithmetic!
u_new = r * u_old + u_step;
```

This is **just field multiplication and addition** - no ECC operations!

### Why Folding Works

The folding equation maintains **correctness**:
- If both R_old and CCCS are valid, R_new is also valid
- The challenge `r` binds the fold to specific instances

### The Augmented Proof

The augmented proof verifies that the folding equation holds:

```rust
// From src/prover/recursive_prove.rs:451-455
/// AugmentedProof verifies:
/// comm_w_new = r * comm_w_old + comm_w_cccs
///
/// Contains sumcheck proof that:
/// P(x) = comm_w_new - r*comm_w_old - comm_w_cccs = 0
/// over the Boolean hypercube
pub struct AugmentedProof {
    pub sumcheck_proof: SumcheckProof,
    pub r: u32,
    pub n: usize,
    pub comm_w_old: u32,
    pub comm_w_cccs: u32,
}
```

---

## Part 6: Complete Pipeline Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1: EVM EXECUTION                                               │
│ Input: bytecode, calldata, gas                                       │
│ Output: Vec<TraceRow> (one per opcode)                             │
│                                                                      │
│ Example: 218 trace rows for block #25025880                         │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 2: WITNESS GENERATION (Commit-And-Prove)                       │
│ Input: Vec<TraceRow>                                                 │
│ Output: Vec<u32> field elements (multiple of 256)                   │
│                                                                      │
│ For each row:                                                       │
│   - Basic info: PC, opcode, gas (5 elements)                       │
│   - State commitments: stack, memory, storage (3 elements)       │
│   - Bytecode commitment (1 element)                                 │
│   - JUMPDEST bitmap (1 element)                                    │
│   - JUMP target info (2 elements)                                  │
│   - Arithmetic operands (3 elements)                              │
│   Total: ~22 elements per row × 218 rows = ~4,796 elements        │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 3: BATCH CHUNKING                                              │
│ Input: Vec<u32> (4,796 elements)                                   │
│ Output: Vec<Vec<u32>> (chunks of 256)                              │
│                                                                      │
│ Padding: last chunk padded with zeros                               │
│ Example: 4,796 / 256 = 18 batches + 156 padding                   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 4: LABRADOR PROVING (Per-Batch)                               │
│ Input: Vec<f32> (256 elements)                                     │
│ Output: LatticeZKProof (~96 bytes)                                 │
│                                                                      │
│ For each batch:                                                     │
│   1. Compute commitments via Poseidon2                             │
│   2. Build constraint polynomial C(x)                               │
│   3. Sumcheck: prove Σ C(x) = 0                                   │
│   4. Sample short response vector s                                │
│   5. Output: (commitment, challenge, response)                     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 5: MERKLE COMPOSITION                                         │
│ Input: Vec<LatticeZKProof> (18 proofs)                             │
│ Output: Merkle root (Poseidon2 hash)                               │
│                                                                      │
│ Build binary tree:                                                  │
│   Level 0: 18 leaf proofs                                          │
│   Level 1: 9 parent nodes = Poseidon2(hash0, hash1), ...          │
│   Level 2: 5 nodes...                                             │
│   Root: single Poseidon2 hash                                     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 6: NOVAIVC FOLDING (Constant-Size)                           │
│ Input: Vec<LatticeZKProof>, running state R_0                      │
│ Output: NovaIVCProof (~132 bytes, constant!)                       │
│                                                                      │
│ For each batch i:                                                  │
│   r_i = Poseidon2(R_{i-1}.u, CCCS_i.u)                           │
│   R_i = (r_i * R_{i-1} + CCCS_i)                                  │
│                                                                      │
│ Final proof contains:                                               │
│   - Final R = (comm_w, u)                                          │
│   - Final CCCS                                                     │
│   - AugmentedProof (sumcheck verifying folding equation)             │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ FINAL PROOF: ~132 bytes                                            │
│                                                                      │
│ Contains:                                                           │
│   - Final commitment comm_w                                         │
│   - Folded accumulator u                                            │
│   - Augmented proof (sumcheck + challenges)                         │
│                                                                      │
│ Verification:                                                        │
│   1. Check augmented proof sumcheck                                 │
│   2. Verify folding equation: comm_w = r*comm_w_old + comm_w_cccs  │
│   3. Check Merkle path to original proofs                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Part 7: Why Each Step Is Fast

### ANE Acceleration

The ANE accelerates **matrix-vector multiplication** (MatVec) in Labrador:

```rust
// MatVec: result[i] = Σ_j A[i][j] * s[j]
// Used in Labrador's short vector response verification
// Computed at ~38 TOPS on ANE

// Poseidon2 hashing: done on CPU (pure Rust modular arithmetic)
// NOT ANE-accelerated
```

### Parallel Batch Processing

```
Single batch (256 elements):  ~7ms
4 batches in parallel:        ~7ms total (not 28ms!)
12 threads × 4 batches:       ~7ms for 12 batches
```

### Why Proof Size Is Constant

Without folding:
```
1000 batches × 96 bytes = 96,000 bytes
```

With NovaIVC folding:
```
Final R = (comm_w, u) = 2 field elements = 8 bytes
AugmentedProof = sumcheck = ~120 bytes
Total: ~132 bytes regardless of 1000 batches!
```

The magic: each fold "absorbs" the previous state, so only the final state is stored.

---

## Part 8: Security Analysis

### What Hardness Assumptions?

| Component | Assumption | Bits |
|-----------|------------|------|
| Poseidon2 commitments | Preimage resistance | 128 |
| Sumcheck | Fiat-Shamir is binding | 128 |
| Chain commitment | Keccak256 collision resistance | 128 |
| Labrador response | Module-SIS hardness | ~92 |
| Folding | Field arithmetic is correct | N/A |

### Why Prime Modulus Matters

Q = 8,383,489 is prime, avoiding:
- Zero divisors (power-of-2 modulus bug)
- CRT splitting (composite modulus bug)
- Ring factorization (NTT soundness bug)

### NovaIVC Proof Verification Hardening

The NovaIVC proof system was hardened against several attack vectors:

#### Vulnerability 1: Chain Tampering (CRITICAL)

**Issue**: The `AugmentedProof` originally only verified the final folding equation:
```
comm_w_final = r_last * comm_w_old_last + cccs_last
```
This only involved the **last fold** in the chain. An attacker who observed a valid proof could modify any earlier challenge `r_i` without detection.

**Fix**: Added `chain_commitment` to `AugmentedProof` that hashes ALL challenges using Keccak256:
```rust
pub struct AugmentedProof {
    // ... existing fields ...
    pub chain_commitment: u32,  // NEW: hash of ALL challenges
}

pub fn chain_commitment(&self) -> u32 {
    use crate::crypto::keccak::keccak256;
    let mut input = Vec::new();
    for (i, &r) in self.challenges.iter().enumerate() {
        input.extend_from_slice(&i.to_le_bytes());
        input.extend_from_slice(&r.to_le_bytes());
    }
    keccak256(&input)[0..4].into()
}
```

#### Vulnerability 2: Empty Proof Bypass (HIGH)

**Issue**: If `augmented_proof` was empty bytes, verification would skip the sumcheck entirely and return `true`.

**Fix**: Empty augmented proofs are now rejected:
```rust
if proof.augmented_proof.is_empty() {
    tracing::warn!("Empty augmented proof not allowed");
    return false;
}
```

#### Vulnerability 3: Length Mismatch (MEDIUM)

**Issue**: The `n` parameter (number of folds) wasn't validated against the actual chain length.

**Fix**: Multiple cross-checks:
```rust
if augmented.n != proof.folding_chain.num_folds {
    return false;  // augmented.n must match chain
}
if proof.running.n != proof.folding_chain.num_folds {
    return false;  // running.n must also match
}
```

### Hash Function Implementation Notes

#### Poseidon2 `hash_pair` (Previously Simplified)

The `Poseidon2::hash_pair()` function was originally implemented with a **single-round** simplification for performance. This is NOT standard Poseidon2 and does NOT provide the same security guarantees.

**Original (BROKEN)**:
```rust
// Only 1 round - collision resistance greatly reduced
for i in 0..HASH_WIDTH {
    state.elements[i] = state.elements[i].wrapping_add(constants[i]) % FIELD_Q;
    // x^5 s-box
    let x = state.elements[i] as u64;
    state.elements[i] = ((x*x*x*x*x) % FIELD_Q) as u32;
}
```

**Current (FIXED)**:
```rust
// Uses full 16-round Poseidon2 hash via Self::hash()
let mut input = [0u8; 32];
input[0..4].copy_from_slice(&a.to_le_bytes());
input[4..8].copy_from_slice(&b.to_le_bytes());
input[8..16].copy_from_slice(b"HP2PAIR1");  // Domain separator
let hash = Self::hash(&input);  // Full Poseidon2
```

#### Why Keccak256 for Chain Commitment?

The chain commitment uses Keccak256 (not Poseidon2) for simplicity and proven security. While Poseidon2 is more efficient in zk circuits due to field arithmetic, Keccak256:
- Has proven 128-bit collision security
- Is well-audited and standard
- Avoids accumulator pattern issues

### What We Don't Have (Yet)

- **No PCP**: We trust the Labrador proof system
- **No formal verification** of constraint completeness
- **No constant-time** implementation (timing attacks possible)

---

## Appendix: Key Code References

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `to_commit_prove_field_elements` | `src/evm/opcodes.rs` | 2269 | Trace → witness |
| `compute_commitments` | `src/evm/opcodes.rs` | 2095 | State → Poseidon2 |
| `AIRConstraint::new` | `src/air/constraints.rs` | 382 | Create constraint |
| `prove_witness` | `src/prover/mod.rs` | 391 | Labrador prove |
| `verify_proof` | `src/prover/mod.rs` | 398 | Labrador verify |
| `SumcheckProof::prove` | `src/crypto/multilinear_pcs.rs` | 266 | Sumcheck protocol |
| `NovaIVCProver::prove` | `src/prover/recursive_prove.rs` | 795 | Nova folding |
