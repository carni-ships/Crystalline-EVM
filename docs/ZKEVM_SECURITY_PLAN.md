# Crystalline-EVM Security Architecture

**Date**: 2026-05-01

Lattice-native zkEVM using ANE-accelerated proving on Apple Silicon.

---

## Current Capabilities

### EVM Compatibility

| Feature | Status |
|---------|--------|
| Opcodes | ~80 supported |
| Precompiles | All 9 standard supported |
| Memory Model | 32-byte reads/writes |
| Stack Safety | Underflow/overflow checked |
| Jump Integrity | JUMPDEST validity enforced |
| Gas Tracking | EIP-1559, refunds, call depth |

### Constraint Modes

| Mode | Security | Description |
|------|----------|-------------|
| StateDiff | Trust-based | Fast state transition verification |
| Minimal | ~80 bits | Basic state validity |
| Medium | ~100 bits | Critical opcode checks |
| Full | ~128 bits | Complete per-row verification |

See [CONSTRAINT_MODES.md](./CONSTRAINT_MODES.md) for detailed security analysis.

---

## Architecture

### Full Stack Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Crystalline-EVM                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    USER LAYER                                    │   │
│  │              Ethereum Block (transactions)                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   EXECUTION LAYER  [CPU]                       │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐              │   │
│  │  │   EVM Exec │  │  revm DIFF │  │  Inspector │              │   │
│  │  └────────────┘  └────────────┘  └────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  CONSTRAINT LAYER  [CPU]                        │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │   │
│  │  │ AIR Checks   │  │ State Transit │  │ Memory/SHA   │        │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │            COMMITMENT LAYER  [CPU + ANE]  ★ LATTICE ★          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │   │
│  │  │  Poseidon2   │  │ Bytecode Merkle│  │ Trace Merkle │        │   │
│  │  │  ★ ANE-acc  │  │              │  │              │        │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │             PROVING LAYER  [CPU + ANE]  ★ LATTICE ★           │   │
│  │  ┌─────────────────────────┐  ┌─────────────────────────┐        │   │
│  │  │   Labrador Prover      │  │    NovaIVC Folding     │        │   │
│  │  │ ★ ANE-accelerated    │  │  prove_opcode_step()   │        │   │
│  │  └─────────────────────────┘  └─────────────────────────┘        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
★ LATTICE ★ = Lattice-based cryptography (Labrador/ML-PCS)
```

### Where Lattices Are Used

| Component | File | Lattice Operation |
|-----------|------|-------------------|
| Poseidon2 Hash | `crypto/poseidon2.rs` | Hash chain for commitments |
| Bytecode Merkle | `evm/mod.rs` | Merkle proofs |
| Witness Builder | `air/polynomial_encoder.rs` | Trace → field elements |
| Labrador Prover | `prover/mod.rs` | SNARK proof generation |
| NovaIVC Folding | `prover/recursive_prove.rs` | LCCCS accumulation |

---

## Design Decisions

### Why Lattice-Based?

| Choice | Rationale |
|--------|------------|
| **No Trusted Setup** | Ceremony-free; security relies on ML-PCS hardness |
| **Custom Field Q=8383489** | Dilithium-3 field for lattice-native operations |
| **Labrador SNARK** | Lattice-based proof system compatible with ANE acceleration |
| **NovaIVC Folding** | Per-opcode proofs with constant-size final proof |

### Formal Verification

Labrador SNARK formal verification is documented in [Anemone's LABRADOR_FORMAL_VERIFICATION.md](../Anemone/docs/LABRADOR_FORMAL_VERIFICATION.md).

---

## Performance

Fixed block #21500000 (76 contracts):

| Mode | Total | Target |
|------|-------|--------|
| StateDiff | 181ms | <12s |
| Minimal | 2580ms | <12s |
| Medium | 1465ms | <12s |
| Full | 1517ms | <12s |

**Per-opcode proving**: ~30ms per opcode with NovaIVC folding.

---

## Key Files

| File | Purpose |
|------|---------|
| `src/evm/full_evm.rs` | revm Inspector integration |
| `src/air/constraints.rs` | AIR constraints |
| `src/evm/opcodes.rs` | Opcode implementations |
| `src/evm/mod.rs` | EVM state and trace |
| `prover/mod.rs` | Labrador prover |
| `prover/recursive_prove.rs` | NovaIVC folding |

---

*Last updated: 2026-05-01*
