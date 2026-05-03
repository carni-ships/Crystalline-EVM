# Crystalline-EVM

**Lattice-native zkEVM using ANE-accelerated proving on Apple Silicon.**

A zero-knowledge Ethereum Virtual Machine that generates proofs using lattice-based cryptography with Apple Neural Engine acceleration.

## Quick Links

- **[Full Documentation](./lattice-evm/README.md)** - Architecture, performance, getting started
- **[Orion Backend](./orion-backend/README.md)** - ANE runtime bindings and Labrador protocol

## Overview

Crystalline-EVM is the **first production zkEVM to use lattice-based SNARKs** (Module-SIS/Module-LWE hardness) instead of STARKs or pairing-based proofs.

```
┌─────────────────────────────────────────────────────────────┐
│  Crystalline-EVM: Lattice-native zkEVM                      │
│                                                             │
│  • L=256 witness size, Q=8,383,489 field                    │
│  • ANE-accelerated MatVec (~2ms per proof)                  │
│  • No trusted setup, post-quantum resistant                 │
│  • 96-byte constant-size proofs                             │
└─────────────────────────────────────────────────────────────┘
```

## Why Lattice-Based?

| Approach | Proof Size | Trusted Setup | Quantum Resistant |
|----------|-----------|--------------|-------------------|
| **Lattice (Crystalline)** | 96 bytes | No | Yes |
| Groth16 | ~200 bytes | Yes | No |
| STARK | 100+ KB | No | Yes |

## Performance

Real-time block processing on M3 Max: ~1.5ms per proof with 100% verification success.

See [lattice-evm/README.md](./lattice-evm/README.md) for detailed benchmarks.

## Repositories

- `lattice-evm/` - Main zkEVM implementation
- `orion-backend/` - ANE runtime and Labrador protocol bindings
- `orion-sys/` - FFI bindings for latticezk library

## License

MIT
