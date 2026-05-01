# Labrador SNARK Formal Verification Plan

**Date**: 2026-05-01
**Status**: Planning
**Target**: Crystalline-EVM Labrador SNARK Implementation

---

## Executive Summary

This document outlines a formal verification plan for the Labrador SNARK implementation used in Crystalline-EVM. Labrador is a lattice-based SNARK (Simplified Dilithium-style) providing non-interactive proofs for zkEVM execution traces.

**Current State**: Implementation complete, tests disabled, no formal verification.
**Goal**: Prove correctness, soundness, and security properties before production use.

---

## 1. Background: Labrador SNARK Protocol

### 1.1 Protocol Overview

Labrador is a **lattice-based SNARK** (not R1CS/CCS-based like Groth16/PLONK):

```
┌─────────────────────────────────────────────────────────────┐
│                  Labrador SNARK Protocol                     │
├─────────────────────────────────────────────────────────────┤
│  Setup:                                                     │
│    - Generate matrix A from seed (expansion)                │
│    - Public parameters: seed, verification key              │
│                                                             │
│  Prove(s, witness):                                        │
│    1. Compute commitment c = A·s mod q (ANE-accelerated)    │
│    2. Generate Fiat-Shamir transcript                      │
│    3. Challenge ch = SHA256(transcript)                    │
│    4. Response r = A·s mod q (short vector decomposition) │
│    5. Output proof = (c, r)                                │
│                                                             │
│  Verify(proof):                                            │
│    1. Recompute commitment from response                    │
│    2. Recompute challenge                                  │
│    3. Check challenge matches                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Q | 8383489 | Prime modulus (Dilithium-3 field) |
| K | 4 | Matrix A row count |
| L | 256 | Matrix A column count (lattice dimension) |
| N | 256 | Polynomial degree |
| λ | 2 | Short vector bound |

### 1.3 RNS Configuration

| Moduli Set | Product | Bits | vs Q |
|------------|---------|------|------|
| {97, 101, 103, 107, 109} | 116,156,147 | ~47 | Q (~23) |

**Critical**: RNS product (~47 bits) must exceed Q (~23 bits) to prevent CRT aliasing.

---

## 2. Verification Goals

### 2.1 Protocol Properties

| Property | Definition | Verification Target |
|----------|------------|-------------------|
| **Completeness** | Honest prover always produces accepting proof | Prove: ∀(pk, witness), Verify(Prove(pk, witness)) = ACCEPT |
| **Soundness** | Cheating prover cannot fool verifier | Prove: ∀proof, Verify(proof) = ACCEPT → prover knows witness |
| **Zero-Knowledge** | Proof reveals nothing about witness | Prove: transcript contains no witness info beyond commitment |
| **Unique Response** | Same witness → deterministic proof | Verify: response is unique function of witness |

### 2.2 Implementation Correctness

| Invariant | Location | Property |
|-----------|----------|----------|
| CRT reconstruction: no aliasing | `latticezk.rs` | RNS product > Q |
| Response bounds: r[i] < Q | `latticezk_verify` | All response elements in range |
| Commitment binding | `latticezk_prove/commit` | A·s committed before challenge |
| Transcript determinism | `fiat_shamir` | Same input → same challenge |
| ANE/CPU consistency | `lattice_ops.rs` | Fallback produces same result |

---

## 3. Formal Verification Tasks

### 3.1 High Priority: Critical Soundness Bugs

#### Task 3.1.1: Transcript Buffer Overflow (CRITICAL)

**Location**: `orion_latticezk.m:260-263`

```c
if (t->len + len > sizeof(t->buffer)) {
    len = sizeof(t->buffer) - t->len;  // SILENT TRUNCATION!
}
```

**Issue**: When buffer overflows, data is truncated silently. A malicious prover could:
1. Truncate transcript to specific length
2. Control challenge output
3. Forge proofs

**Verification Steps**:
1. Formalize transcript buffer as finite array with max size
2. Prove: appending data beyond buffer bounds does not affect challenge
3. Alternatively: prove buffer cannot overflow (append always checks bounds)

**Fix Required**: Either:
- Enlarge buffer to handle max transcript
- Return error on overflow (no silent truncation)

**Severity**: CRITICAL - Could enable proof forgery

---

#### Task 3.1.2: Response Bounds Not Enforced in Prover

**Location**: `latticezk_prove()` does not check response bounds before output

```c
// Response computed but NOT validated:
for (int i = 0; i < LATTICEZK_L; i++) {
    proof->response[i] = (uint32_t)(A_s[i] + 0.5f) % LATTICEZK_Q;
}
```

**Issue**: A buggy ANE/CPU implementation could produce out-of-bounds response values, causing verify to reject valid proofs or (in some formulations) accept invalid ones.

**Verification Steps**:
1. Prove: ∀valid witness s, Prove(s) produces response r where r[i] < Q
2. Prove: ∀r where r[i] ≥ Q, Verify rejects (or handles correctly)

**Fix Required**: Add bounds check in prover before serialization

---

#### Task 3.1.3: Matrix Expansion Not Cryptographically Secure

**Location**: `latticezk_expand_a()`

```c
int8_t val = (int8_t)(seed[idx] ^ (uint8_t)(i * 17 + 31));
A[i] = (float)val / 64.0f;
```

**Issue**: XOR with linear function is NOT a cryptographic expansion. An attacker who learns any column of A can recover the seed and generate arbitrary proofs.

**Verification Steps**:
1. Prove: Matrix A is indistinguishable from random under seed secrecy
2. Analyze: XOR+linear is equivalent to LFSR with known feedback
3. Recommend: Replace with SHAKE128 or AES-based expansion

**Fix Required**: Use proper cryptographic hash function (SHAKE128-256)

**Severity**: HIGH - Could break binding property

---

### 3.2 Medium Priority: Implementation Correctness

#### Task 3.2.1: RNS CRT Reconstruction Correctness

**Location**: `rns.rs`, `latticezk.rs`

**Verification Goal**: Prove RNS product exceeds Q, no aliasing occurs

```
∀a, b ∈ [0, Q):
  CRT(a mod p_i) = CRT(b mod p_i)  ⇔  a ≡ b (mod Q)
```

**Verification Steps**:
1. Verify RNS product P = ∏p_i > Q
2. Verify Q and p_i are coprime
3. Prove CRT reconstruction is unique mod P
4. Since P > Q and Q | P (implied by construction), reconstruction mod Q is unique

**Current Status**: Comment in code claims P > Q, but not formally verified

---

#### Task 3.2.2: ANE/CPU Consistency

**Location**: `lattice_ops.rs:176-184`

```rust
pub fn matvec_cpu(&mut self, A: &[f32], s: &[f32]) -> Vec<f32> {
    // CPU fallback - should produce identical output to ANE
}
```

**Verification Goal**: ANE path and CPU path produce bit-identical results

**Verification Steps**:
1. Define formal specification of matvec: A ∈ Z_Q^{K×L}, s ∈ Z_Q^L, output = A·s mod Q
2. Prove: ANE path output ≡ CPU path output (mod Q)
3. Test: Generate random A, s, verify outputs match

**Challenge**: ANE uses fp16, CPU uses f32. Need tolerance analysis.

---

#### Task 3.2.3: Fiat-Shamir Determinism

**Location**: `fiat_shamir.rs`, `orion_latticezk.m`

**Verification Goal**: Same transcript always produces same challenge

**Verification Steps**:
1. Model transcript as append-only buffer
2. Prove: appending same data in same order → same SHA256 hash
3. Prove: SHA256 is deterministic (standard hash property)
4. Verify: No use of timestamps, random, or other non-deterministic inputs in transcript

**Current Issue**: Seed generation uses nanoseconds (`generate_seed()`) - should use transcript-derived randomness only

---

### 3.3 Lower Priority: Security Properties

#### Task 3.3.1: Zero-Knowledge Property

**Verification Goal**: Proof reveals nothing about witness beyond commitment

**Analysis Required**:
1. Transcript includes: commitment c, not witness s
2. Challenge ch = SHA256(c || ...) - no s
3. Response r = A·s - but s is multiplied by A, then hashed in commitment
4. Need to show: given (c, ch, r), no info about s beyond c

**Approach**: Show that for any valid proof, there exists a simulator that produces identical distribution without knowing s

---

#### Task 3.3.2: Soundness Under Byzantine ANE

**Verification Goal**: Even if ANE is compromised/malicious, soundness holds

**Scenario**:
1. ANE returns wrong matvec result
2. Prover signs incorrect proof
3. Verifier should reject

**Verification Steps**:
1. Prove: Verify only checks commitment consistency, not matvec directly
2. If ANE cheats: commitment will be inconsistent with response
3. Verify will recompute commitment from response and detect mismatch

**Note**: This relies on commitment binding - need to verify separately

---

## 4. Verification Methods

### 4.1 Mechanized Proof Assistants

**Recommended**: Lean 4 with the Mathlib library

| Component | Tool | Rationale |
|-----------|------|-----------|
| Protocol proofs | Lean 4 | Algebraic structures, modular arithmetic |
| Rust code verification | Rust Horn verification (CBMC, KLEE) | Bounded model checking |
| Floating-point analysis | Fluctuat | ANE fp16 behavior |

### 4.2 Testing Strategy

**Fuzz Testing**:
```rust
// Property-based test: same input → same output
fn fuzz_fiat_shamir(seed: Vec<u8>, data: Vec<Vec<u8>>) {
    let mut transcript = Transcript::new(&seed);
    for d in data {
        transcript.append(&d);
    }
    let ch1 = transcript.challenge();
    let ch2 = {
        let mut t2 = Transcript::new(&seed);
        for d in &data { t2.append(d); }
        t2.challenge()
    };
    assert_eq!(ch1, ch2);
}
```

**Differential Testing**:
```rust
// ANE vs CPU must match
fn fuzz_matvec_consistency(A: Vec<f32>, s: Vec<f32>) {
    let cpu = matvec_cpu(&A, &s);
    let ane = matvec_ane(&A, &s);
    assert_eq!(cpu, ane);  // Within fp16 tolerance
}
```

### 4.3 Formal Specification Language

```lean
-- Lattice-based SNARK specification
structure LabradorParams where
  Q : ℕ  -- prime modulus
  K : ℕ  -- matrix rows
  L : ℕ  -- matrix cols
  λ : ℕ  -- short vector bound

structure Proof (P : LabradorParams) where
  commitment : Fin 256 → ℤ
  response  : Fin 256 → ℤ

-- Completeness theorem
theorem completeness (pk : ProvingKey) (w : Witness) :
  Verify(pk, Prove(pk, w)) = true := by sorry

-- Soundness theorem
theorem soundness (pk : ProvingKey) (π : Proof) :
  Verify(pk, π) = true → ∃ w, π = Prove(pk, w) := by sorry
```

---

## 5. Recommended Fixes Before Verification

### 5.1 Critical Fixes (Before Any Production Use)

| Issue | Fix | Priority |
|-------|-----|----------|
| Transcript overflow | Return error, enlarge buffer | CRITICAL |
| Response bounds | Add check in prover | CRITICAL |
| Weak matrix expansion | Replace with SHAKE128-256 | HIGH |

### 5.2 Recommended Improvements

| Issue | Fix | Priority |
|-------|-----|----------|
| Deterministic seed | Use proof seed from outside, not timestamp | MEDIUM |
| Test infrastructure | Enable tests in CI with mock ANE | MEDIUM |
| Bounds analysis | fp16 tolerance documentation | MEDIUM |

---

## 6. Timeline Estimate

| Phase | Tasks | Effort |
|-------|-------|--------|
| **Phase 1: Critical Fixes** | Fix transcript overflow, response bounds, matrix expansion | 1 week |
| **Phase 2: Protocol Correctness** | Completeness, soundness, ZK proofs (Lean) | 4-6 weeks |
| **Phase 3: Implementation** | Rust code verification, ANE/CPU consistency | 2-3 weeks |
| **Phase 4: Integration** | E2E tests, fuzzing, production readiness | 2 weeks |

**Total Estimate**: 9-14 weeks for full formal verification

---

## 7. References

### 7.1 Protocol References

- **Dilithium**: [CRYPTO 2017](https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf) - Base protocol
- **Labrador**: [Labrador SNARK paper]() - Lattice SNARK for zkEVM (internal reference)
- **Fiat-Shamir**: [FOCS 1986](https://ia.cr/2017/550) - Transform for non-interactive proofs

### 7.2 Implementation References

- `orion_latticezk.m` - Core ANE implementation
- `latticezk.rs` - Rust wrapper
- `rns.rs` - RNS number system
- `fiat_shamir.rs` - Transcript implementation

### 7.3 Verification References

- **Lean 4**: https://leanprover.github.io/
- **CBMC**: https://www.cprover.org/cbmc/
- **Fluctuat**: https://www-list.cea.fr/Licence/en/Fluctuat.html

---

## 8. Open Questions

1. **Q**: Should we replace the simplified matrix expansion with a full SHAKE128 implementation?
   **A**: Yes, but need to verify performance impact on ANE throughput

2. **Q**: Can we use formal verification to prove ANE hardware security (byzantine fault tolerance)?
   **A**: No - ANE is black box. Soundness relies on commitment binding, not ANE correctness.

3. **Q**: Should we move to a proven protocol (like Dory) instead of Labrador?
   **A**: Dory is transparent (no trusted setup) but slower. Consider for future iteration.

---

*Document version: 1.0*
*Last updated: 2026-05-01*
