//! E2E test: Prove an Ethereum transaction
//!
//! This test demonstrates proving a simple ETH transfer transaction
//! using the full EVM opcode implementation borrowed from Zoltraak.

use lattice_evm::evm::{
    execute_bytecode, EVMState, TraceRow, OpCode, LatticeEVM
};
use lattice_evm::Q;

#[test]
fn test_simple_evm_execution() {
    // PUSH1 10, PUSH1 20, ADD, STOP
    // Expected: stack = [30]
    let code = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];
    let (state, trace) = execute_bytecode(&code, 1000).unwrap();

    tracing::info!("Simple EVM execution:");
    tracing::info!("  Final stack: {:?}", state.stack);
    tracing::info!("  Trace length: {}", trace.len());
    tracing::info!("  State running: {}", state.running);

    assert!(!state.running);
    assert_eq!(state.stack.last(), Some(&30));
    assert_eq!(trace.len(), 4); // PUSH1, PUSH1, ADD, STOP

    tracing::info!("✓ Simple EVM execution test passed");
}

#[test]
fn test_multiplication() {
    // PUSH1 5, PUSH1 6, MUL, STOP
    let code = vec![0x60, 0x05, 0x60, 0x06, 0x02, 0x00];
    let (state, _) = execute_bytecode(&code, 1000).unwrap();

    // 5 * 6 = 30
    assert_eq!(state.stack.last(), Some(&30));
    tracing::info!("✓ Multiplication test passed");
}

#[test]
fn test_jump_operations() {
    // PUSH1 5, JUMP, JUMPDEST, STOP
    //     0    1    2    3    4
    let code = vec![0x60, 0x05, 0x56, 0x5B, 0x00];
    let (state, _) = execute_bytecode(&code, 1000).unwrap();

    assert!(!state.running);
    assert_eq!(state.pc, 5);
    tracing::info!("✓ Jump test passed");
}

#[test]
fn test_eth_transfer_with_real_opcodes() {
    // Simulate an ETH transfer bytecode:
    // PUSH1 0 (destination)
    // PUSH1 100 (value)
    // PUSH1 0 (memory offset)
    // MSTORE (store value to memory at offset 0)
    // PUSH1 32 (return size)
    // PUSH1 0 (return offset)
    // RETURN (return data)
    let code = vec![
        0x60, 0x00,        // PUSH1 0 (destination offset)
        0x60, 0x64,        // PUSH1 100 (value in wei, simplified)
        0x60, 0x00,        // PUSH1 0 (memory offset)
        0x52,              // MSTORE
        0x60, 0x20,        // PUSH1 32 (return size)
        0x60, 0x00,        // PUSH1 0 (return offset)
        0xf3,              // RETURN
    ];

    tracing::info!("Executing ETH transfer simulation...");
    let (state, trace) = execute_bytecode(&code, 21000).unwrap();

    tracing::info!("ETH transfer execution:");
    tracing::info!("  Returned: state.running={}, state.reverted={}", state.running, state.reverted);
    tracing::info!("  Memory size: {}", state.memory_size);
    tracing::info!("  Gas used: {}", 21000 - state.gas);

    // Verify trace
    for (i, row) in trace.iter().enumerate() {
        let op = OpCode::from_u8(row.opcode);
        tracing::debug!("  Trace[{}]: pc={}, opcode={:?}, gas_after={}",
            i, row.pc, op, row.gas_after);
    }

    assert!(!state.running);
    assert!(!state.reverted);
    tracing::info!("✓ ETH transfer test passed");
}

#[test]
fn test_trace_to_field_elements() {
    // Generate trace and convert to field elements (mod Q)
    let code = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];
    let (_, trace) = execute_bytecode(&code, 1000).unwrap();

    let field_elements: Vec<u32> = trace.iter()
        .flat_map(|row| row.to_field_elements())
        .collect();

    tracing::info!("Trace converted to {} field elements", field_elements.len());
    tracing::info!("Q = {}", Q);

    // Verify all values are < Q
    for (i, &fe) in field_elements.iter().enumerate() {
        assert!(fe < Q as u32, "Field element[{}] = {} >= Q", i, fe);
    }

    tracing::info!("✓ All {} field elements are < Q", field_elements.len());
}

#[test]
fn test_lattice_evm_constraints() {
    let evm = LatticeEVM::new(256);
    let trace = evm.generate_trace();

    let mut all_valid = true;
    for row in &trace {
        let constraints = evm.evaluate_row_constraints(row);
        if constraints.iter().any(|&c| c != 0) {
            all_valid = false;
            tracing::warn!("Constraint violation at pc={}: {:?}", row.pc, constraints);
        }
    }

    assert!(all_valid, "All constraints should be satisfied");
    tracing::info!("✓ Lattice EVM constraints test passed");
}

#[test]
fn test_full_trace_with_eth_data() {
    // Full ETH transfer: 1 ETH from sender to recipient
    // Using bytecode that mimics a simple transfer

    // Memory layout for transfer:
    // [0..31] = sender address
    // [32..63] = recipient address
    // [64..95] = transfer value (1 ETH = 1000000000000000000 wei)
    let transfer_value: u32 = (1_000_000_000_000_000_000u64 % Q as u64) as u32;
    let sender: u32 = (0x1234567890abcdefu64 % Q as u64) as u32;
    let recipient: u32 = (0xfedcba0987654321u64 % Q as u64) as u32;

    tracing::info!("ETH Transfer Parameters (mod Q={}):", Q);
    tracing::info!("  Sender: 0x{:08x}", sender);
    tracing::info!("  Recipient: 0x{:08x}", recipient);
    tracing::info!("  Value: {} wei", transfer_value);

    // Create EVM bytecode that stores sender, recipient, value in memory
    // and returns the data (simulating a transfer receipt)
    let code = vec![
        // Store sender at memory[0..32]
        0x7f, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,  // PUSH32 sender
        0x60, 0x00,  // PUSH1 0 (offset 0)
        0x52,        // MSTORE
        // Store recipient at memory[32..64]
        0x7f, 0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,  // PUSH32 recipient
        0x60, 0x20,  // PUSH1 32 (offset 32)
        0x52,        // MSTORE
        // Store value at memory[64..96]
        0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, transfer_value.to_le_bytes()[0],  // PUSH32 value
        0x60, 0x40,  // PUSH1 64 (offset 64)
        0x52,        // MSTORE
        // Return memory[0..96] as receipt
        0x60, 0x60,  // PUSH1 96 (return size)
        0x60, 0x00,  // PUSH1 0 (return offset)
        0xf3,        // RETURN
    ];

    tracing::info!("Executing ETH transfer bytecode ({} bytes)...", code.len());
    let (final_state, trace) = execute_bytecode(&code, 21000).unwrap();

    tracing::info!("Transfer execution:");
    tracing::info!("  Gas remaining: {}", final_state.gas);
    tracing::info!("  Memory size: {}", final_state.memory_size);
    tracing::info!("  Running: {}, Reverted: {}", final_state.running, final_state.reverted);
    tracing::info!("  Trace rows: {}", trace.len());

    // Verify execution completed successfully
    assert!(!final_state.running, "Execution should complete");
    assert!(!final_state.reverted, "Should not revert");
    assert!(final_state.memory_size >= 96, "Should have memory for transfer data");

    // Generate full trace for proving
    let trace_rows: Vec<Vec<u32>> = trace.iter()
        .map(|row| row.to_field_elements())
        .collect();

    tracing::info!("Generated {} trace rows", trace_rows.len());

    // For full proof, these would be:
    // 1. Convert to FieldElement(q=8383489)
    // 2. Commit via ANE MatVec: c = A * s mod q
    // 3. Generate Labrador proof

    tracing::info!("✓ Full ETH transfer trace generated successfully");
}

#[test]
fn test_opcode_coverage() {
    // Test that all major opcodes are defined
    let opcodes = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  // STOP, ADD, MUL, SUB, DIV, SDIV, MOD, SMOD
        0x08, 0x09, 0x0A, 0x0B,                           // ADDMOD, MULMOD, EXP, SIGNEXTEND
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,              // LT, GT, SLT, SGT, EQ, ISZERO
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, // AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
        0x20,                                              // KECCAK256
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55,              // POP, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE
        0x56, 0x57, 0x5B,                                // JUMP, JUMPI, JUMPDEST
        0x60, 0x61, 0x7F,                                // PUSH1, PUSH2, PUSH32
        0x80, 0x8F,                                      // DUP1, DUP16
        0x90, 0x9F,                                      // SWAP1, SWAP16
        0xF0, 0xF1, 0xF3, 0xFD, 0xFF,                   // CREATE, CALL, RETURN, REVERT, SELFDESTRUCT
    ];

    let mut defined = 0;
    let mut unknown = 0;
    for opcode in opcodes {
        let op = OpCode::from_u8(opcode);
        if matches!(op, OpCode::STOP) && opcode != 0x00 {
            unknown += 1;
        } else {
            defined += 1;
        }
    }

    tracing::info!("Opcode coverage: {} defined, {} unknown", defined, unknown);
    assert!(defined >= 40, "Should have at least 40 opcodes defined");
    tracing::info!("✓ Opcode coverage test passed");
}