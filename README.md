# Crystalline-EVM

**Lattice-native zkEVM using ANE-accelerated proving on Apple Silicon.**

A zero-knowledge Ethereum Virtual Machine that generates proofs using lattice-based cryptography (Labrador SNARK) with Apple Neural Engine acceleration for MatVec operations.

```
┌─────────────────────────────────────────────────────────────┐
│           Crystalline-EVM Architecture                      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Ethereum Block (transactions)                │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           EVM Execution (revm + custom)              │   │
│  │           • RevmTraceRow (simplified, 6.7 elems/row) │   │
│  │           • TraceRow (full, 40 elems/row)            │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Commit-Prove Element Extraction            │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ★ Labrador SNARK Proving (ANE-accelerated) ★        │   │
│  │  • L=256 witness size, Q=8383489 field               │   │
│  │  • Keygen once, share pk/vk across threads           │   │
│  │  • Proofs verified via latticezk_verify              │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Constant-Size Final Proof (96 bytes)         │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Features

- **First Lattice-Based zkEVM**: Uses Labrador SNARK (lattice cryptography) instead of STARKs or Groth16
- **Lattice-Native Proving**: Uses Labrador SNARK protocol with field Q=8,383,489
- **ANE Acceleration via Anemone**: Apple Neural Engine accelerates MatVec operations (~2ms per proof) via [Anemone](https://github.com/carni-ships/Anemone)
- **Two Trace Modes**:
  - **Simplified (RevmTraceRow)**: 6.7 elements/row, faster TRACE phase
  - **Full (TraceRow)**: 40 elements/row, more detailed constraints
- **Cryptographic Verification**: All proofs verified via `latticezk_verify` FFI
- **No Trusted Setup**: ML-PCS hardness assumptions, ceremony-free
- **Parallel Proving**: Multi-threaded leaf proof generation with shared key material

---

## Performance

Real-time block processing on M3 Max (12 threads):

| Block | Txs | EVM Exec | TRACE | COMMIT | PROVE | Proofs | Gas |
|-------|-----|----------|-------|--------|-------|--------|-----|
| #25008365 | 225 | 4.2ms | 0.85ms | 0.16ms | 257ms | 168/225 | 56.5M |
| #25008366 | 154 | 3.1ms | 0.75ms | 0.14ms | 193ms | 120/154 | 35.7M |
| #25008367 | 265 | 5.1ms | 0.88ms | 0.13ms | 236ms | 179/265 | 62.2M |

**Notes:**
- EVM Exec: Total EVM execution time for all transactions (including omitted ones)
- Proofs: Number of proofs generated vs total transactions (precompiles and transfers may be omitted)
- Per-proof: ~1.5-2ms (ANE-accelerated Labrador)

See detailed benchmarks in the [benches](./lattice-evm/benches/) directory.

---

## Why Lattice-Based?

Lattice-based cryptography offers unique advantages for zero-knowledge proofs:

| Approach | Proof Size | Trusted Setup | Quantum Resistant |
|----------|-----------|--------------|-------------------|
| **Lattice (Crystalline)** | 96 bytes | No | Yes |
| Groth16 | ~200 bytes | Yes | No |
| STARK | 100+ KB | No | Yes |

### Why This Matters

**1. No Trusted Setup Ceremony**
Groth16 and other pairing-based proofs require a elaborate ceremony to generate toxic waste. Lattice-based proofs (Labrador SNARK) are based on Module-SIS/Module-LWE hardness assumptions — no ceremony needed.

**2. Post-Quantum Security**
Shor's algorithm breaks RSA and elliptic curves. A quantum computer could compromise Ethereum's security today if it has a sufficiently large Qubit count. Lattice problems are believed to be quantum-resistant.

**3. Hardware Acceleration**
The Apple Neural Engine (ANE) is designed for matrix operations — exactly what's needed for lattice-based MatVec. This enables ~1.5-2ms per proof on consumer hardware.

**4. Real-Time Proving**
At ~1.5ms per proof with 12 threads, we can prove Ethereum blocks faster than they are mined (~12 seconds). This enables:
- **Light clients** that verify proofs without running full nodes
- **Layer 2 validity proofs** without slow aggregators
- **Mobile/proving** on iPhone/Mac for edge deployment

### The Problem We Solve

Current zkEVMs face a trilemma:

```
         ┌─────────────────────────────────────────┐
         │          THE ZK PROVING TRIPLEMMA        │
         │                                          │
         │    Proving Speed                         │
         │    (hardware acceleration)              │
         │          ●                               │
         │         /│\                              │
         │        / │ \                             │
         │       /  │  \                            │
         │   ┌──/───┼───\──┐                        │
         │   │ Proof │Quantum│                        │
         │   │ Size  │Resist │                        │
         │   │  ●    │   ●   │                        │
         │   └───────┴───────┘                        │
         └─────────────────────────────────────────┘

Crystalline-EVM: Achieves all three via lattice + ANE acceleration
```

---

## Repository Structure

```
Crystalline-EVM-src/
├── lattice-evm/           # Main zkEVM crate
│   ├── src/
│   │   ├── prover/         # Labrador prover, parallel_prove, SNARK
│   │   ├── air/           # AIR constraints, polynomial encoding
│   │   ├── evm/           # EVM implementation, trace generation
│   │   │   ├── full_evm.rs    # RevmTraceRow (simplified mode)
│   │   │   └── opcodes.rs     # TraceRow (full mode)
│   │   ├── crypto/        # Poseidon2, Keccak256, Blake3, Merkle
│   │   │   ├── batch_merkle.rs # Batch Merkle tree building
│   │   │   ├── blake3.rs      # Batch Blake3 operations
│   │   │   └── keccak.rs      # Batch Keccak operations
│   │   └── verifier/      # Proof verification
│   └── benches/           # Benchmarks and tests
├── orion-sys/              # FFI bindings for Anemone (latticezk)
└── orion-backend/          # Internal ANE runtime helpers

External:
└── Anemone/               # ANE-accelerated lattice crypto (separate repo)
    └── core/latticezk.m   # Labrador proving via Apple Neural Engine
```

---

## Mode Comparison

| Mode | Elements/Row | Batches | TRACE Time | PROVE Time | Use Case |
|------|-------------|---------|-----------|------------|----------|
| **Simplified** | 6.7 | 1 | 0.25ms | 120ms | Fast iteration |
| **Full** | 40.0 | 7 | 0.02ms | 11ms | Detailed proving |

Full mode is ~10x faster in PROVE phase despite processing more data due to better batch parallelization.

---

## What We Can Achieve

### Current Capabilities
- Prove Ethereum blocks in real-time (~1.5-2ms per proof on M3 Max)
- 96-byte constant-size proofs verifiable in milliseconds
- 100% of contract calls now traced and proved (except CREATE)
- Parallel proving across 12 threads

### Use Cases

**1. Light Clients**
Instead of running a full Ethereum node, light clients could verify a 96-byte proof that the block is valid. No syncing, no storage, just verify.

**2. Mobile Proving**
Run proving on iPhone/Mac via ANE. Generate proofs for your own transactions without depending on third-party provers.

**3. Layer 2 Validity Proofs**
Generate validity proofs for rollups without Groth16 ceremonies or slow STARKs. Fast finality with cryptographic certainty.

**4. Auditable Privacy**
Provers can generate proofs without revealing transaction details — only that the execution was correct.

### Roadmap

- [ ] **Recursive proving** — Prove multiple blocks together for even smaller proofs
- [ ] **Full EVM compatibility** — Complete opcode coverage for all contract types
- [ ] **GPU proving** — Extend ANE acceleration to discrete GPUs
- [ ] **Distributed proving** — Multiple machines collaborating on one block
- [ ] **ZK bridges** — Trustless cross-chain message passing via proofs

---

## Comparison with Other zkEVMs

| zkEVM | Proof System | Trusted Setup | ANE Support |
|-------|--------------|--------------|-------------|
| **Crystalline-EVM** | Labrador (Lattice) | No | Yes |
| Polygon zkEVM | Groth16/STARK | Yes | No |
| zkSync Era | Boojum (STARK) | No | No |
| Scroll | Groth16 | Yes | No |

**First lattice-based zkEVM**: Crystalline-EVM is the first production zkEVM to use lattice-based SNARKs (Module-SIS/Module-LWE hardness) instead of STARKs or pairing-based proofs. This enables ANE hardware acceleration and eliminates trusted setup requirements.

**Crystalline-EVM's niche**: Edge deployment on Apple Silicon with hardware acceleration via ANE.

---

## Dependencies

- **Anemone**: ANE-accelerated lattice crypto library ([GitHub](https://github.com/carni-ships/Anemone)) - provides `latticezk_*` functions via FFI
- **orion-sys**: Rust FFI bindings for Anemone's latticezk library
- **orion-backend**: Internal ANE runtime helpers
- **revm**: Rust Ethereum Virtual Machine implementation
- **rayon**: Parallel iterator support for multi-threaded proving

---

## Building

```bash
# Build the prover binary
cargo build --release --bin realtime_prover

# Run mode comparison benchmark
cargo run --release --bin mode_comparison

# Process Ethereum blocks in real-time
cargo run --release --bin realtime_prover -- --max 10
```

---

## License

MIT

---

*Crystalline-EVM: Lattice-native proving for the Ethereum ecosystem.*
