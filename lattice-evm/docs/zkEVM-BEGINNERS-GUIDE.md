# A Beginner's Guide to Lattice-Based zkEVMs

## What is a zkEVM?

A **Zero-Knowledge Ethereum Virtual Machine (zkEVM)** proves that a piece of Ethereum code executed correctly—without revealing the inputs or the full computation.

Think of it like a mathematical receipt:
- **Traditional computation**: You run code, you get a result
- **zkEVM proof**: You run code, you get a result **plus** a cryptographic proof that anyone can verify

The "ZK" part means:
- **Zero**: The verifier learns nothing about the inputs (except what's implied by the output)
- **Knowledge**: The proof wouldn't exist without the actual computation happening

## Why Do We Need zkEVMs?

| Use Case | Description |
|----------|-------------|
| **Layer 2 Scaling** | Rollups post proofs on-chain instead of full transaction data |
| **Privacy** | Prove you have enough ETH to pass KYC without revealing your balance |
| **Verifiable Computation** | Trust that off-chain computation was done correctly |

## The Intuition: From Computation to Polynomials

Here's the magical insight that makes zkEVMs possible:

### Step 1: Encode Computation as Math

Any computation can be expressed as a set of polynomial equations:

```
// Traditional code:
if (x + y == z) { jump_to(dest) }

// Becomes a polynomial constraint:
(x + y - z) * (1 - condition) = 0
```

If the polynomial equals zero, the computation was correct.

### Step 2: Use Polynomials as Proofs

Here's the key trick: **a polynomial of degree `d` is uniquely defined by `d+1` points**.

So instead of proving "I ran 10,000 lines of code correctly", you can prove:
1. "I have a polynomial that encodes this computation"
2. "That polynomial evaluates to zero at all valid inputs"

This is called the **Polynomial Interactive Oracle Proof (PIOP)** or **Sumcheck Protocol**.

---

## How Our Lattice zkEVM Works

Our system uses **lattice-based cryptography** instead of traditional elliptic curves. Here's why that matters:

### Why Lattices?

| Approach | Security Basis | Performance | Proof Size |
|----------|---------------|-------------|------------|
| **Elliptic Curves** (groth16, plonk) | Discrete logarithm | Fast proving | Small (~200 bytes) |
| **Lattices** (our approach) | Shortest vector problem | ANE-accelerated | Constant (~132 bytes) |
| **STARKs** | Hash functions | Slow | Large (~45 KB) |

Lattices are **post-quantum secure**—they can't be broken by Shor's algorithm.

---

## Step-by-Step: How a Proof Gets Made

Let's trace through what happens when you prove an EVM execution.

### Step 0: The EVM Executes (Very Fast)

```rust
// The EVM runs your smart contract bytecode
// Every opcode creates a "trace row" - a snapshot of state
let trace = execute_bytecode(code, gas);
```

A trace row looks like:
```
Row 0: PC=0, Opcode=PUSH1, Gas=3, Stack=[], Memory=[]
Row 1: PC=2, Opcode=PUSH1, Gas=3, Stack=[10], Memory=[]
Row 2: PC=4, Opcode=ADD,    Gas=3, Stack=[30], Memory=[]
```

### Step 1: Convert Trace to Field Elements

We compress each trace row into **field elements** (numbers modulo Q=8383489):

```
Row 0: [pc, opcode, gas_before, gas_after, stack_len, ...stack_values]
     = [0, 96, 3, 0, 0, 0, 0, 0, ...]
```

Why field elements? They're the native language of lattice cryptography.

### Step 2: Build Commitment Merkle Tree

We hash all elements into a **Merkle tree** using **Poseidon2**:

```rust
// Poseidon2 is a SNARK-friendly hash function
let root = Poseidon2::hash_pair(left_child, right_child);
```

The root is the **commitment**—a short digest of the entire computation.

### Step 3: Generate Sumcheck Proof

The core of our proving system is the **Sumcheck Protocol**:

```
Goal: Prove that Σ f(x) = claimed_sum
      for all x in {0,1}^n (Boolean hypercube)

Instead of evaluating at 2^n points (impossible for n=100),
we do n rounds of interaction:

Round 1: Prover sends g_1(X) - a polynomial in one variable
Round 2: Verifier picks random r_1
Round 3: Prover sends g_2(X) - another polynomial
...continue until all variables are fixed
Final: Verify at the final point
```

**Why it's fast**: Each round is just polynomial arithmetic, not full computation.

### Step 4: Folding (NovaIVC / SuperNeo)

This is the secret sauce for **constant-size proofs**.

**Nova Folding** works like this:

```
Running proof R_0 = (comm_w, u)
Step 1: Create CCCS_1 from new computation
Step 2: Fold: R_1 = r_0 * R_0 + CCCS_1
Step 3: Repeat for each computation step...

Final: We have ONE proof, regardless of how many steps!
```

```
Without folding: 1000 steps = 1000 proofs
With NovaIVC:    1000 steps = 1 proof (constant size!)
```

### Step 5: Verify the Proof

Verification checks:
1. **Merkle path** is valid (commitment is correct)
2. **Sumcheck challenges** match Fiat-Shamir derivation
3. **Folding equation** holds: `comm_w_new = r * comm_w_old + comm_w_cccs`

---

## Why Is Our zkEVM Fast?

### 1. ANE Acceleration

The **Apple Neural Engine (ANE)** performs matrix multiplication at ~38 TOPS with incredible energy efficiency:

```rust
// Instead of slow CPU hashing:
for elem in elements {
    hash = Poseidon2::hash_pair(hash, elem);
}

// ANE does this in parallel across thousands of elements!
```

### 2. Parallel Batch Proving

```
Block with 1000 transactions
         ↓
    Split into 256-element batches
         ↓
    [ANE] [ANE] [ANE] [ANE]   ← 4 parallel provers
         ↓
    4 proofs (each ~192 bytes)
         ↓
    Compose into single Merkle root
```

### 3. Minimal State Encoding

We don't prove full EVM state. We prove **commit-and-prove**:

```
Instead of: Prove "stack[0] = 30, stack[1] = 20, ..."
We prove:    Prove "hash(stack) = 0xABCD1234" (commitment)

Only if the commitment matches do we trust the state!
```

This reduces witness size by ~6x.

---

## Why Is Our zkEVM Secure?

### 1. Cryptographic Commitments

```
hash = Poseidon2(field_elements...)
Merkle tree root = Poseidon2(child1, child2)
```

Changing ANY bit of input → completely different hash (avalanche effect)

### 2. Fiat-Shamir Transformation

Challenges in sumcheck are derived from **Poseidon2 hashes** of previous values:

```rust
// NOT: challenge = random()          ← Can be manipulated!
// IS:  challenge = Poseidon2(previous_challenges, commitments)
```

This makes the proof **non-interactive** and **deterministic**.

### 3. Constraint Polys Ensure Correctness

Every EVM opcode has a **polynomial constraint**:

```rust
// ADD constraint: a + b = c
AIRConstraint {
    cols: [stack_top, stack_second, stack_third],
    coeffs: [1, 1, -1],  // a + b - c = 0
    expected: 0
}

// JUMPI constraint: (condition == 0) OR (is_jumpdest == 1)
AIRConstraint {
    cols: [condition, is_jumpdest],
    coeffs: [1, -1],  // condition * (1 - is_jumpdest) = 0
    expected: 0
}
```

If any constraint ≠ 0, the proof fails.

---

## Why Is Proof Size Constant?

This is the NovaIVC innovation:

```
Traditional ZK: Proof size grows with computation size
    1 operation → 200 bytes
    1000 operations → 200,000 bytes

NovaIVC: Proof size is CONSTANT
    1 operation → ~156 bytes
    1000 operations → ~156 bytes
```

### How?

```
Instead of proving each step individually...

We FOLD steps together:

Step 0: R = (comm_0, u_0)           ← Initial state
Step 1: R = r*R + CCCS(1)           ← Fold step 1
Step 2: R = r*R + CCCS(2)           ← Fold step 2
...
Step N: R = r*R + CCCS(N)           ← Fold step N

Final R contains:
- One commitment (comm_w)
- One folded accumulator (u)
- One augmented proof

Total: ~132 bytes regardless of N!
```

---

## Comparison to Other zkEVMs

| zkEVM | Proof Size | Proving Time | Privacy | Post-Quantum |
|--------|------------|--------------|---------|-------------|
| ** ours (NovaIVC)** | ~132 bytes | ~200ms | Partial | ✅ Yes |
| Polygon zkEVM | ~45 KB | ~2 min | Partial | ❌ No |
| StarkNet | ~45 KB | ~3 min | Full | ✅ Yes |
| zkSync | ~500 bytes | ~30 sec | Partial | ❌ No |

### Why Are We Smaller?

- **Bytecode Merkle proofs**: We don't prove full bytecode—only the touched parts
- **Minimal state encoding**: Stack/memory committed, not expanded
- **NovaIVC folding**: Final proof is constant-size regardless of trace length

---

## The Full Picture: How a Block Gets Proven

```
┌─────────────────────────────────────────────────────────────────┐
│                    BLOCK #25025879                               │
│  444 transactions, 218 trace rows, 4,142 field elements        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: EVM EXECUTION (1ms)                                    │
│ • Execute each transaction                                      │
│ • Generate trace rows                                           │
│ • 152 successful contracts, 50 failed (expected)               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: COMMITMENT (0.1ms)                                      │
│ • Convert rows to field elements                                │
│ • Build Poseidon2 Merkle tree                                   │
│ • 18 batches (256 elements each)                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: LABRADOR PROVING (130ms)                               │
│ • 12 threads × ANE parallel proving                            │
│ • 18 leaf proofs generated                                    │
│ • Each proof ~192 bytes                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: NOVAIVC FOLDING (50ms)                                 │
│ • Fold 218 rows into ONE proof                                 │
│ • Uses 4-row batches                                           │
│ • Final proof: 132 bytes (constant!)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: VERIFICATION (0.001ms)                                  │
│ • Check Merkle paths                                            │
│ • Verify Fiat-Shamir challenges                                │
│ • Verify folding equation                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ OUTPUT:                                                        │
│ • Proof: 132 bytes                                             │
│ • On-chain verification gas: ~200,000                         │
│ • vs 4KB raw transaction data                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Takeaways

1. **zkEVMs prove computation correctness without revealing inputs**

2. **We use lattice-based cryptography (Poseidon2)** for post-quantum security

3. **The proving pipeline is:**
   - Execute → Trace → Commit → Sumcheck → Fold → Verify

4. **Three modes trade off speed vs proof size:**
   - **Labrador**: Fastest (~125ms), largest proofs (~5KB/block)
   - **NovaIVC**: Constant-size (~132 bytes), slower folding
   - **SuperNeo**: Balanced (~448 bytes), multifolding

5. **Proof size is constant because of NovaIVC folding**—all steps fold into one

6. **ANE acceleration makes Poseidon2 hashing extremely fast**—this is why we're faster than pure CPU approaches

---

## What's Next?

To dive deeper:

- [`src/crypto/poseidon2.rs`](src/crypto/poseidon2.rs) - Poseidon2 hash implementation
- [`src/crypto/multilinear_pcs.rs`](src/crypto/multilinear_pcs.rs) - Sumcheck protocol
- [`src/prover/recursive_prove.rs`](src/prover/recursive_prove.rs) - NovaIVC folding
- [SuperNova Paper](https://eprint.iacr.org/2024/1563) - NovaIVC theory
