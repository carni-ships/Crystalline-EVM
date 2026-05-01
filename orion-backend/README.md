# Orion Backend for Noir ACIR

An ACIR backend for lattice-based ZK using:
- **Orion ANE** for high-throughput MatVec (1,098 GFLOPS)
- **Orion GPU NTT** for polynomial multiplication
- **Labrador/Greyhound** protocols for proof system

## Architecture

```text
Noir Code → ACIR (msgpack-compact) → Orion Backend → Proof
                                      ├── ANE MatVec
                                      ├── GPU NTT
                                      └── CRT Reconstruction
```

## Project Structure

```
orion-backend/
├── src/
│   ├── lib.rs              # Core types and definitions
│   ├── acir_parser.rs      # ACIR deserialization
│   ├── opcode_handler.rs   # Opcode routing
│   ├── lattice_ops.rs      # Lattice operations (ANE/GPU)
│   ├── brillig_runner.rs   # Brillig bytecode execution
│   └── error.rs            # Error types
├── sys/
│   ├── Cargo.toml
│   ├── build.rs            # cbindgen build script
│   └── src/lib.rs          # FFI bindings
├── Cargo.toml
└── README.md
```

## Building

```bash
cd orion-backend
cargo build
```

## Usage

```bash
# Show backend info
cargo run --example simple -- --info

# Process ACIR file
cargo run --example simple -- circuit.acir
```

## Supported ACIR Opcodes

| Opcode | Handler | Hardware |
|--------|---------|----------|
| AssertZero | `handle_assert_zero()` | - |
| BlackBoxFuncCall | `handle_blackbox()` | ANE/GPU |
| MemoryOp | `handle_memory()` | - |
| BrilligCall | `handle_brillig()` | - |
| Call | `handle_call()` | - |

## Black Box Functions

| Function | Hardware | Description |
|----------|----------|-------------|
| MatVec | ANE | Matrix-vector multiplication |
| NTT | GPU | Number-theoretic transform |
| CRT | CPU | CRT reconstruction |
| Poseidon2 | ANE | SNARK-friendly hash |

## Key Design Decisions

### 1. ACIR Extension vs Brillig

Using **Hybrid approach**:
- MatVec → new `LATTICE_MATVEC` opcode (ANE is specialized)
- NTT/CRT → Brillig (flexible)

### 2. RNS Bridge

ACIR uses one field (typically BN254). Lattice ZK needs q=8383489.

Solution: Express lattice ops as Brillig/unconstrained, proving happens on constraints over ACIR field.

### 3. FFI Strategy

FFI bindings auto-generated via `cbindgen` from Orion C headers:
- `orion_latticezk.h` - MatVec, Labrador protocol
- `orion_gpu_ntt.h` - GPU NTT
- `orion_rns.h` - CRT reconstruction

## References

- [ACIR Spec](../zkMetal/docs/acir_spec.md) - ACIR opcode structure
- [Labrador Protocol](../Orion/core/orion_latticezk.m) - Lattice proof system
- [Dilithium Parameters](../Orion/core/orion_latticezk.h) - q=8383489, k=l=4, n=256