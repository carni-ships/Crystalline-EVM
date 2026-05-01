# zkEVM Prover Benchmarks

**Date**: 2026-05-01
**Binary**: `improved_unified_prover`
**Hardware**: Apple M3 Pro (MacBook Pro)
**Test**: Ethereum block #21,500,000 (~76 contracts)

---

## Constraint Mode Performance

| Mode | Execution | Proving | Total | Target | Status |
|------|-----------|---------|-------|--------|--------|
| **StateDiff** | 48ms | 133ms | 181ms | <12s | PASS |
| **Minimal** | 2572ms | 8ms | 2580ms | <12s | PASS |
| **Medium** | 1456ms | 9ms | 1465ms | <12s | PASS |
| **Full** | 1508ms | 9ms | 1517ms | <12s | PASS |

**Per-opcode proving**: ~30ms per opcode with NovaIVC folding

---

## Speedup Analysis

### Revm Speedup for StateDiff

StateDiff uses revm directly instead of custom interpreter:

| Metric | Custom EVM | revm | Improvement |
|--------|-----------|------|-------------|
| Execution | 395ms | 147ms | **2.7x faster** |
| Total | 510ms | 300ms | **1.7x faster** |

### Why StateDiff is Fast

1. Uses revm for EVM execution (highly optimized)
2. Skips per-row trace analysis entirely
3. Only extracts state diff (storage changes)

### What "Execution" Includes

The execution time includes:
1. **EVM execution via revm** - Running bytecode to generate trace
2. **Trace analysis** - Walking the trace for constraint checking
3. **Commitment computation** - Hash chains for Merkle proofs

StateDiff only does #1 (with minimal trace work), skipping #2 and #3.

---

## Usage

```bash
# StateDiff (fastest, trust-based)
ZKEVM_CONSTRAINT_MODE=statediff ./improved_unified_prover

# Full (default, highest security)
ZKEVM_CONSTRAINT_MODE=full ./improved_unified_prover

# Medium (balanced)
ZKEVM_CONSTRAINT_MODE=medium ./improved_unified_prover

# Minimal (fast, basic checks)
ZKEVM_CONSTRAINT_MODE=minimal ./improved_unified_prover
```

---

## Security vs Performance Tradeoff

See [CONSTRAINT_MODES.md](./CONSTRAINT_MODES.md) for detailed security analysis.

---

## Related

- **ANE benchmarks**: See [Anemone benchmarks](../Anemone/docs/BENCHMARKS.md)
- **Formal verification**: See [Labrador verification plan](../Anemone/docs/LABRADOR_FORMAL_VERIFICATION.md)

---

*Last updated: 2026-05-01*
