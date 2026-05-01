# Orion Backend

Lattice-based ZK proving backend using Labrador SNARK protocol.

## Modules

| Module | Purpose |
|--------|---------|
| `labrador` | Labrador SNARK prover and verifier |
| `lattice_ops` | ANE-accelerated MatVec operations |

## Building

```bash
cd orion-backend
cargo build
```

## Features

- `mock` - Use mock FFI for testing without ANE hardware
