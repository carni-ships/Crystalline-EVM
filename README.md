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
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           AIR Constraint Checking                     │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ★ Labrador SNARK Proving (ANE-accelerated) ★       │   │
│  │  • Poseidon2 hashing (ANE MatVec)                   │   │
│  │  • NovaIVC folding for per-opcode proofs              │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Constant-Size Final Proof                    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Features

- **Lattice-Native Proving**: Uses Labrador SNARK protocol with custom field Q=8383489
- **Per-Opcode Proofs**: NovaIVC folding produces constant-size proofs regardless of trace length
- **ANE Acceleration**: Apple Neural Engine accelerates Poseidon2 hashing and MatVec operations
- **No Trusted Setup**: Ceremony-free proving using ML-PCS hardness assumptions
- **EVM Compatible**: Supports ~80 EVM opcodes with full constraint checking

---

## Why Lattice-Based zkEVM?

Traditional zkEVMs rely on Groth16 or STARKs, both with significant tradeoffs:

**Groth16**: Requires a trusted ceremony (toxic waste),circuit-specific setup, and is vulnerable to quantum attack.

**STARKs**: No trusted setup, quantum-resistant, but proofs are massive (100+ KB) and verification is slow.

**Lattice SNARKs** (Labrador) offer a third path:
- **No ceremony**: No toxic waste, no trusted setup required
- **Post-quantum**: Security based on lattice problems (SVP/CVP)
- **Small proofs**: Constant-size proofs like Groth16, but without the setup
- **Fast verification**: Field arithmetic, not elliptic curves

Apple Silicon's **Neural Engine (ANE)** provides massive acceleration for the MatVec operations that dominate lattice proving. The ANE's 60+ GFLOPS at 1W enables proving on-device—imagine a future iPhone generating zkEVM proofs.

---

## Performance

Benchmarked on block #21,500,000 (76 contracts):

| Mode | Execution | Total | Target | Status |
|------|-----------|-------|--------|--------|
| StateDiff | 48ms | 181ms | <12s | PASS |
| Minimal | 2572ms | 2580ms | <12s | PASS |
| Medium | 1456ms | 1465ms | <12s | PASS |
| Full | 1508ms | 1517ms | <12s | PASS |

**Per-opcode proving**: ~30ms per opcode with NovaIVC folding

---

## Repository Structure

```
Crystalline-EVM-src/
├── lattice-evm/           # Main zkEVM crate
│   ├── src/
│   │   ├── prover/        # Labrador prover, NovaIVC, SNARK
│   │   ├── air/           # AIR constraints, polynomial encoding
│   │   ├── evm/           # EVM implementation, trace generation
│   │   ├── crypto/        # Poseidon2, Keccak256, Merkle trees
│   │   └── verifier/     # Proof verification
│   └── benches/           # Benchmarks
├── orion-backend/         # ANE runtime bindings (Apple Neural Engine)
├── core/                  # Shared types
└── docs/                  # Documentation
```

---

## Quick Start

```rust
use lattice_evm::prover::{Prover, ProverConfig};

// Create prover (ANE will be used automatically if available)
let prover = Prover::new(ProverConfig::default())?;
println!("ANE available: {}", prover.ane_available());

// Generate proof for bytecode execution
let proof = prover.prove_evm_trace(&bytecode, gas_limit)?;
```

---

## Architecture

### Constraint Modes

| Mode | Constraints | Security | Speed | Use Case |
|------|-------------|----------|-------|----------|
| **StateDiff** | Minimal | Trust-based | Fastest | State verification only |
| **Minimal** | Basic | ~80 bits | Fast | Simple contract calls |
| **Medium** | +Memory | ~100 bits | Medium | Standard DeFi |
| **Full** | +Cross-row | ~128 bits | Most thorough | Security-critical |

For detailed security analysis, see [docs/CONSTRAINT_MODES.md](docs/CONSTRAINT_MODES.md).

### Proving Pipeline

1. **Execution**: EVM bytecode runs, trace generated
2. **Constraint Check**: AIR constraints verified per row
3. **Commitment**: Poseidon2 hash chains for bytecode/storage Merkle trees
4. **Witness Build**: Trace → field elements (padded to LATTICEZK_L=256)
5. **Labrador Prove**: ANE-accelerated MatVec for SNARK witness generation
6. **NovaIVC Fold**: Per-opcode proofs folded into constant-size accumulator

---

## Comparison with Other zkEVMs

| zkEVM | Proof System | Trusted Setup | ANE Support |
|-------|--------------|--------------|-------------|
| **Crystalline-EVM** | Labrador (Lattice) | No | Yes |
| Polygon zkEVM | Groth16/STARK | Yes | No |
| zkSync Era | Boojum (STARK) | No | No |
| Scroll | Groth16 | Yes | No |

**Crystalline-EVM's niche**: Edge deployment on Apple Silicon with hardware acceleration via ANE.

---

## Related Projects

- **[Anemone](https://github.com/carni-ships/Anemone)**: ANE acceleration primitives for lattice-based ZK. Crystalline-EVM uses Anemone for MatVec and Poseidon2 operations.
- **[Labrador](https://github.com/carni-ships/labrador)**: Lattice SNARK protocol (ML-PCS based) used for proof generation.
- **[revm](https://github.com/bluealloy/revm)**: High-performance Ethereum Virtual Machine implementation in Rust.

---

## License

MIT

---

*Crystalline-EVM: Lattice-native proving for the Ethereum ecosystem.*
