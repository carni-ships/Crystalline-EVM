# Crystalline-EVM

**Lattice-native zkEVM using ANE-accelerated proving on Apple Silicon.**

A zero-knowledge Ethereum Virtual Machine that generates proofs using lattice-based cryptography (Labrador SNARK) with Apple Neural Engine acceleration for MatVec operations.

```
┌─────────────────────────────────────────────────────────────┐
│           Crystalline-EVM Architecture                      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Ethereum Block (transactions)               │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           EVM Execution (revm + custom)             │   │
│  │           • RevmTraceRow (simplified, 6.7 elems/row)  │   │
│  │           • TraceRow (full, 40 elems/row)           │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Commit-Prove Element Extraction             │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ★ Labrador SNARK Proving (ANE-accelerated) ★       │   │
│  │  • L=256 witness size, Q=8383489 field             │   │
│  │  • Keygen once, share pk/vk across threads           │   │
│  │  • Proofs verified via latticezk_verify (cryptographic)│   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Constant-Size Final Proof (96 bytes)        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Features

- **Lattice-Native Proving**: Uses Labrador SNARK protocol with field Q=8,383,489
- **ANE Acceleration**: Apple Neural Engine accelerates MatVec operations (~2ms per proof)
- **Two Trace Modes**:
  - **Simplified (RevmTraceRow)**: 6.7 elements/row, faster TRACE phase
  - **Full (TraceRow)**: 40 elements/row, more detailed constraints
- **Cryptographic Verification**: All proofs verified via `latticezk_verify` FFI
- **No Trusted Setup**: ML-PCS hardness assumptions, ceremony-free
- **Parallel Proving**: Multi-threaded leaf proof generation with shared key material

---

## Performance

Real-time block processing on M3 Max (12 threads):

| Block | Txs | Calls | Proofs | TRACE | COMMIT | PROVE | Gas |
|-------|-----|-------|--------|-------|--------|-------|-----|
| #25008365 | 225 | 171 | 168 | 0.85ms | 0.16ms | 257ms | 56.5M |
| #25008366 | 154 | 128 | 120 | 0.75ms | 0.14ms | 193ms | 35.7M |
| #25008367 | 265 | 203 | 179 | 0.88ms | 0.13ms | 236ms | 62.2M |

**Per-proof**: ~1.5-2ms (ANE-accelerated Labrador)

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
│   └── benches/           # Benchmarks (mode_comparison, block_benchmark)
├── orion-backend/          # ANE runtime bindings (Apple Neural Engine)
└── orion-sys/              # FFI bindings for latticezk library
```

---

## Quick Start

```rust
use lattice_evm::prover::{Prover, ProverConfig};

// Create prover with ANE hardware
let prover = Prover::new(ProverConfig::default())?;
println!("ANE available: {}", prover.ane_available());

// Prove a batch of elements (256 elements per witness)
let witness: Vec<f32> = elements.iter().map(|&v| v as f32).collect();
let proof = prover.prove_witness(&witness)?;

// Verify the proof (cryptographically)
let valid = prover.verify_proof(&proof)?;
```

---

## Mode Comparison

| Mode | Elements/Row | Batches | TRACE Time | PROVE Time | Use Case |
|------|-------------|---------|-----------|------------|----------|
| **Simplified** | 6.7 | 1 | 0.25ms | 120ms | Fast iteration |
| **Full** | 40.0 | 7 | 0.02ms | 11ms | Detailed proving |

Full mode is ~10x faster in PROVE phase despite processing more data due to better batch parallelization.

---

## Security Model

Labrador protocol security parameters:
- **Q = 8,383,489** (prime field modulus)
- **K = 4** (RNS residues for CRT representation)
- **L = 256** (witness dimension, equals lattice dimension N)
- **λ = 2.0** (short vector sampling parameter)

Proof size: **96 bytes** (commitment + challenge + response)

---

## Architecture

### Proving Pipeline

1. **Trace**: Execute EVM bytecode, generate trace rows
2. **Extract**: Convert trace to field elements (mod Q)
3. **Chunk**: Pad to 256-element batches (Labrador L parameter)
4. **Prove**: ANE-accelerated MatVec for each batch (parallel across threads)
5. **Verify**: Cryptographic verification via `latticezk_verify`
6. **Commit**: Poseidon2 Merkle tree for batch commitments

### Prover Optimization

- **Keygen once**: Shared pk/vk material created before spawning threads
- **Thread-local provers**: Each thread creates its own prover from shared key
- **Inline verification**: Each proof verified immediately after generation

---

## Comparison with Other zkEVMs

| zkEVM | Proof System | Trusted Setup | ANE Support |
|-------|--------------|--------------|-------------|
| **Crystalline-EVM** | Labrador (Lattice) | No | Yes |
| Polygon zkEVM | Groth16/STARK | Yes | No |
| zkSync Era | Boojum (STARK) | No | No |
| Scroll | Groth16 | Yes | No |

**Crystalline-EVM's niche**: Edge deployment on Apple Silicon with hardware acceleration via ANE. No trusted setup required.

---

## Dependencies

- **orion-backend**: ANE runtime for Apple Neural Engine access
- **orion-sys**: FFI bindings for Labrador protocol (latticezk)
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