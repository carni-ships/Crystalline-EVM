# Crystalline-EVM Security Architecture

**Date**: 2026-05-01

Lattice-native zkEVM using ANE-accelerated proving on Apple Silicon.

---

## Current Capabilities

### EVM Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| Opcodes | ~80/140 | Many arithmetic opcodes not implemented (SDIV, SMOD, ADDMOD, MULMOD, EXP, SHL, SHR, SAR, etc.) |
| Precompiles | Simplified | Cryptographic verification simplified; gas checks only |
| Memory Model | Partial | Values truncated to u32 mod Q, not full u256 |
| Storage Model | Vec-based | Not a proper Sparse Merkle Tree |
| Call Context | Simulation | DELEGATECALL/STATICCALL/CALLCODE return 1, not actual execution |
| Block Context | Dummy values | Blockhash, timestamp, coinbase all hardcoded |
| Transaction Types | BERLIN only | EIP-2930 (access lists) and EIP-4844 (blobs) not supported |
| EIP-1559 | Partial | Base fee burn and priority fee not verified |

### Constraint Modes

| Mode | Security Bits | Description | Production Ready? |
|------|---------------|-------------|------------------|
| StateDiff | Trust-based | Fast state transition verification | ⚠️ Limited verification |
| Minimal | ~80 bits | Basic state validity | ⚠️ Missing opcodes |
| Medium | ~100 bits | Critical opcode checks | ⚠️ Incomplete EVM |
| Full | ~128 bits | Complete per-row verification | ❌ EVM semantics incomplete |

**Security Bits**: Approximate security level against collision attacks, not EVM correctness.

See [CONSTRAINT_MODES.md](./CONSTRAINT_MODES.md) for detailed security analysis.

---

## Known Gaps vs Production zkEVMs

Crystalline-EVM is **not yet equivalent** to Polygon zkEVM, zkSync Era, or Scroll. Key gaps:

### Critical Gaps

| Gap | Impact | What's Needed |
|-----|--------|---------------|
| Missing ~60 opcodes | Most DeFi uses SDIV, SMOD, ADDMOD, MULMOD, EXP, SHL, SHR, SAR | Full opcode implementation |
| Call context simulation | Proxy contracts (Extensensive in DeFi) don't work | Real nested execution via revm Inspector |
| Storage as Vec | No state proofs | Sparse Merkle Tree implementation |
| Memory truncated to u32 mod Q | Values > 8.3M overflow | Full u256 memory operations |

### High Priority Gaps

| Gap | Impact | What's Needed |
|-----|--------|---------------|
| Block context hardcoded | Time-lock, oracle contracts fail | Real block data injection |
| EIP-4844 blobs | Blob transactions unverifiable | Blob transaction type, KZG verification |
| EIP-1559 partial | Post-London gas incorrect | Base fee burn, priority fee handling |
| Transaction types | EIP-2930 access lists unsupported | Access list transaction support |

### Medium Priority

| Gap | Impact |
|-----|--------|
| Precompile verification simplified | ECRecover/BN128 could return wrong results |
| EIP-2929 access lists | Cold/warm storage gas not differentiated |
| EIP-6780 SELFDESTRUCT | Post-6780 semantics not implemented |

---

## Comparison with Production zkEVMs

| Feature | Polygon zkEVM | zkSync Era | Scroll | Crystalline |
|---------|--------------|------------|--------|-------------|
| Opcodes | ~140 full | ~140 full | ~140 full | ~80 partial |
| Storage | SMT | SMT + Bookkeeping | SMT | Vec<(u32,u32)> |
| Memory | Full u256 | Full u256 | Full u256 | u32 mod Q |
| Tx Types | All | All | All | BERLIN only |
| Call Context | Full nested | Full nested | Full nested | Simulation |
| ANE Acceleration | No | No | No | **Yes (unique)** |

**Crystalline's advantage**: Only zkEVM with ANE acceleration. But EVM semantics must be complete before this matters for production.

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
