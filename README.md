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

## Performance

Benchmarked on block #21,500,000 (76 contracts):

| Mode | Execution | Total | Target | Status |
|------|-----------|-------|--------|--------|
| StateDiff | 48ms | 181ms | <12s | ✅ |
| Minimal | 2572ms | 2580ms | <12s | ✅ |
| Medium | 1456ms | 1465ms | <12s | ✅ |
| Full | 1508ms | 1517ms | <12s | ✅ |

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

| Mode | Constraints | Speed | Use Case |
|------|-------------|-------|----------|
| **StateDiff** | Minimal | Fastest | State verification only |
| **Minimal** | Basic | Fast | Simple contract calls |
| **Medium** | +Memory | Medium | Standard DeFi |
| **Full** | +Cross-row | Most thorough | Security-critical |

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

## Dependencies

- **orion-backend**: ANE runtime for Apple Neural Engine access
- **revm**: Rust Ethereum Virtual Machine implementation
- **labrador**: Lattice SNARK protocol (ML-PCS based)

---

## License

MIT

---

*Crystalline-EVM: Lattice-native proving for the Ethereum ecosystem.*
