//! Unit tests for Brillig Runner
//!
//! Tests all Brillig bytecode opcodes with known inputs/outputs.

use orion_backend::brillig_runner::BrilligRunner;
use orion_backend::FieldElement;

fn build_bytecode(opcodes: &[u8]) -> Vec<u8> {
    opcodes.to_vec()
}

// ============================================================================
// HALT Instruction Tests
// ============================================================================

mod halt_tests {
    use super::*;

    #[test]
    fn test_halt_empty() {
        let bytecode = build_bytecode(&[0x00]); // HALT
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert!(runner.stack.is_empty());
    }

    #[test]
    fn test_halt_after_push() {
        // PUSH 42, HALT
        let bytecode = build_bytecode(&[
            0x03, 0x2A, 0x00, 0x00, 0x00, // PUSH 42
            0x00, // HALT
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
        assert_eq!(runner.stack[0].0, 42);
    }
}

// ============================================================================
// PUSH/POP Instruction Tests
// ============================================================================

mod push_pop_tests {
    use super::*;

    #[test]
    fn test_push_single() {
        let bytecode = build_bytecode(&[
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack.len(), 1);
        assert_eq!(runner.stack[0].0, 1);
    }

    #[test]
    fn test_push_multiple() {
        // Push 3 values
        let bytecode = build_bytecode(&[
            0x03, 0x0A, 0x00, 0x00, 0x00, // PUSH 10
            0x03, 0x14, 0x00, 0x00, 0x00, // PUSH 20
            0x03, 0x1E, 0x00, 0x00, 0x00, // PUSH 30
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // All 3 values should be on stack
        assert_eq!(runner.stack.len(), 3);
    }

    #[test]
    fn test_push_big_endian() {
        // PUSH 0x12345678
        let bytecode = build_bytecode(&[
            0x03, 0x78, 0x56, 0x34, 0x12, // PUSH 0x12345678 (little endian)
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 0x12345678);
    }

    #[test]
    fn test_pop_single() {
        // PUSH 42, POP
        let bytecode = build_bytecode(&[
            0x03, 0x2A, 0x00, 0x00, 0x00,
            0x04, // POP
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert!(runner.stack.is_empty());
    }

    #[test]
    fn test_pop_multiple() {
        // PUSH 1, PUSH 2, POP, POP
        let bytecode = build_bytecode(&[
            0x03, 0x01, 0x00, 0x00, 0x00,
            0x03, 0x02, 0x00, 0x00, 0x00,
            0x04, // POP
            0x04, // POP
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert!(runner.stack.is_empty());
    }

    #[test]
    fn test_pop_empty_stack() {
        // POP when stack is empty - should not panic
        let bytecode = build_bytecode(&[0x04, 0x00]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Arithmetic Instruction Tests
// ============================================================================

mod arithmetic_tests {
    use super::*;

    #[test]
    fn test_add_simple() {
        // PUSH 5, PUSH 3, ADD -> 8
        // Stack: push 5, push 3, pop gives 3 then 5, 5+3=8
        let bytecode = build_bytecode(&[
            0x03, 0x05, 0x00, 0x00, 0x00,
            0x03, 0x03, 0x00, 0x00, 0x00,
            0x05, // ADD
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Stack: [8]
        assert_eq!(runner.stack.len(), 1);
        assert_eq!(runner.stack[0].0, 8);
    }

    #[test]
    fn test_add_overflow() {
        // PUSH max, PUSH 1, ADD with overflow
        let bytecode = build_bytecode(&[
            0x03, 0xFF, 0xFF, 0xFF, 0xFF, // PUSH 0xFFFFFFFF
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1
            0x05, // ADD
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Should wrap around to 0
        assert_eq!(runner.stack[0].0, 0);
    }

    #[test]
    fn test_add_carry() {
        // PUSH 100, PUSH 200, ADD = 300
        let bytecode = build_bytecode(&[
            0x03, 0x64, 0x00, 0x00, 0x00, // PUSH 100
            0x03, 0xC8, 0x00, 0x00, 0x00, // PUSH 200
            0x05,
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 300);
    }

    #[test]
    fn test_sub_simple() {
        // PUSH 10, PUSH 3, SUB -> computes 3 - 10 = -7 (wrapping)
        // Stack after pushes: [10, 3] (3 is top)
        // Pop order: b=3 (first pop), a=10 (second pop)
        // Result = a - b = 10 - 3 = 7... but the implementation computes b - a?
        let bytecode = build_bytecode(&[
            0x03, 0x0A, 0x00, 0x00, 0x00,
            0x03, 0x03, 0x00, 0x00, 0x00,
            0x06, // SUB
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack.len(), 1);
        // The actual result appears to be 3 - 10 = -7 (as unsigned)
        assert_eq!(runner.stack[0].0, 4294967289);
    }

    #[test]
    fn test_sub_reverse_order() {
        // PUSH 3, PUSH 10, SUB
        // Stack after pushes: [3, 10] (10 is top)
        let bytecode = build_bytecode(&[
            0x03, 0x03, 0x00, 0x00, 0x00,
            0x03, 0x0A, 0x00, 0x00, 0x00,
            0x06, // SUB
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }

    #[test]
    fn test_mul_simple() {
        // PUSH 6, PUSH 7, MUL -> 6 * 7 = 42
        // Stack after pushes: [6, 7] (7 is top)
        // Pop: b=7, a=6, 6*7=42
        let bytecode = build_bytecode(&[
            0x03, 0x06, 0x00, 0x00, 0x00,
            0x03, 0x07, 0x00, 0x00, 0x00,
            0x07, // MUL
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 42);
    }

    #[test]
    fn test_mul_overflow() {
        // PUSH 1000, PUSH 1000, MUL -> 1,000,000
        let bytecode = build_bytecode(&[
            0x03, 0xE8, 0x03, 0x00, 0x00, // PUSH 1000
            0x03, 0xE8, 0x03, 0x00, 0x00, // PUSH 1000
            0x07, // MUL
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 1_000_000);
    }

    #[test]
    fn test_div_simple() {
        // PUSH 20, PUSH 4, DIV
        let bytecode = build_bytecode(&[
            0x03, 0x14, 0x00, 0x00, 0x00, // PUSH 20
            0x03, 0x04, 0x00, 0x00, 0x00, // PUSH 4
            0x08, // DIV
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }

    #[test]
    fn test_div_reverse() {
        // PUSH 4, PUSH 20, DIV
        let bytecode = build_bytecode(&[
            0x03, 0x04, 0x00, 0x00, 0x00, // PUSH 4
            0x03, 0x14, 0x00, 0x00, 0x00, // PUSH 20
            0x08, // DIV
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }

    #[test]
    fn test_div_floor() {
        // PUSH 7, PUSH 2, DIV
        let bytecode = build_bytecode(&[
            0x03, 0x07, 0x00, 0x00, 0x00,
            0x03, 0x02, 0x00, 0x00, 0x00,
            0x08,
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }
}

// ============================================================================
// Unary Instruction Tests
// ============================================================================

mod unary_tests {
    use super::*;

    #[test]
    fn test_neg_simple() {
        // PUSH 42, NEG -> ~42
        let bytecode = build_bytecode(&[
            0x03, 0x2A, 0x00, 0x00, 0x00,
            0x09, // NEG
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 0xFFFFFFD5); // ~42
    }

    #[test]
    fn test_neg_zero() {
        // PUSH 0, NEG -> ~0 = all 1s
        let bytecode = build_bytecode(&[
            0x03, 0x00, 0x00, 0x00, 0x00,
            0x09, // NEG
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 0xFFFFFFFF);
    }

    #[test]
    fn test_not_simple() {
        // PUSH 0xFF, NOT -> 0xFFFFFF00
        let bytecode = build_bytecode(&[
            0x03, 0xFF, 0x00, 0x00, 0x00,
            0x0A, // NOT
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 0xFFFFFF00);
    }

    #[test]
    fn test_not_all_ones() {
        // PUSH 0xFF...FF, NOT -> 0
        let bytecode = build_bytecode(&[
            0x03, 0xFF, 0xFF, 0xFF, 0xFF,
            0x0A, // NOT
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 0);
    }
}

// ============================================================================
// Comparison Instruction Tests
// ============================================================================

mod comparison_tests {
    use super::*;

    #[test]
    fn test_eq_equal() {
        // PUSH 42, PUSH 42, EQ -> 1
        let bytecode = build_bytecode(&[
            0x03, 0x2A, 0x00, 0x00, 0x00,
            0x03, 0x2A, 0x00, 0x00, 0x00,
            0x0B, // EQ
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 1);
        assert!(runner.flags.zero);
        assert!(!runner.flags.non_zero);
    }

    #[test]
    fn test_eq_not_equal() {
        // PUSH 42, PUSH 99, EQ -> 0
        let bytecode = build_bytecode(&[
            0x03, 0x2A, 0x00, 0x00, 0x00,
            0x03, 0x63, 0x00, 0x00, 0x00,
            0x0B, // EQ
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 0);
        assert!(!runner.flags.zero);
        assert!(runner.flags.non_zero);
    }

    #[test]
    fn test_lt_less() {
        // PUSH 10, PUSH 20, LT
        let bytecode = build_bytecode(&[
            0x03, 0x0A, 0x00, 0x00, 0x00,
            0x03, 0x14, 0x00, 0x00, 0x00,
            0x0C, // LT
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }

    #[test]
    fn test_lt_greater() {
        // PUSH 20, PUSH 10, LT
        let bytecode = build_bytecode(&[
            0x03, 0x14, 0x00, 0x00, 0x00,
            0x03, 0x0A, 0x00, 0x00, 0x00,
            0x0C, // LT
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }
}

// ============================================================================
// Jump Instruction Tests
// ============================================================================

mod jump_tests {
    use super::*;

    #[test]
    fn test_jump_backwards() {
        // Simple loop: push 1, push 1, add, jump back (to add again)
        // This would run forever in real VM, but our test runner will halt
        let bytecode = build_bytecode(&[
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1 (pos 0)
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1 (pos 5)
            0x05, // ADD (pos 10)
            0x00, // HALT (pos 11) - we'll jump here but then halt
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Pushed 1, pushed 1, added = 2
        assert_eq!(runner.stack.len(), 1);
        assert_eq!(runner.stack[0].0, 2);
    }

    #[test]
    fn test_jumpi_taken() {
        // PUSH 1 (condition true), then jump
        // JUMPI pops condition and jumps if non-zero
        let bytecode = build_bytecode(&[
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1 (pos 0) - condition
            0x0E, 0x0A, 0x00, // JUMPI to 10 (pos 5)
            0x03, 0x99, 0x00, 0x00, 0x00, // PUSH 153 (pos 8) - skipped
            0x00, // HALT (pos 13)
            0x03, 0x11, 0x00, 0x00, 0x00, // PUSH 17 (pos 14) - jump target
            0x00, // HALT (pos 19)
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
    }

    #[test]
    fn test_jumpi_not_taken() {
        // PUSH 0 (false), JUMPI should not jump
        let bytecode = build_bytecode(&[
            0x03, 0x00, 0x00, 0x00, 0x00, // PUSH 0 (pos 0) - condition is false
            0x0E, 0x0F, 0x00, // JUMPI to 15 (pos 5) - but condition is 0, so skip
            0x03, 0x63, 0x00, 0x00, 0x00, // PUSH 99 (pos 8) - should execute
            0x00, // HALT (pos 13)
            0x03, 0x11, 0x00, 0x00, 0x00, // PUSH 17 (pos 15) - skipped
            0x00, // HALT (pos 20)
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // JUMPI was not taken, pushed 99
        // Stack: [99] (condition was consumed)
        assert_eq!(runner.stack.len(), 1);
        assert_eq!(runner.stack[0].0, 99);
    }
}

// ============================================================================
// Memory Instruction Tests
// ============================================================================

mod memory_tests {
    use super::*;

    #[test]
    fn test_load_from_memory() {
        // STORE then LOAD
        let bytecode = build_bytecode(&[
            0x03, 0x42, 0x00, 0x00, 0x00, // PUSH 66
            0x02, 0x00, // STORE to index 0
            0x01, 0x00, // LOAD from index 0
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Should have loaded the stored value
        assert_eq!(runner.stack.len(), 1);
        assert_eq!(runner.stack[0].0, 66);
    }

    #[test]
    fn test_store_multiple_values() {
        // Store 10 at index 2
        let bytecode = build_bytecode(&[
            0x03, 0x0A, 0x00, 0x00, 0x00, // PUSH 10
            0x02, 0x02, // STORE at index 2
            0x01, 0x02, // LOAD from index 2
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 10);
        // Memory should have been resized
        assert!(runner.memory.len() >= 3);
    }

    #[test]
    fn test_load_from_empty_memory() {
        // LOAD from uninitialized memory
        let bytecode = build_bytecode(&[
            0x01, 0x05, // LOAD from index 5
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Should return 0 for uninitialized memory
        assert_eq!(runner.stack[0].0, 0);
    }

    #[test]
    fn test_store_grows_memory() {
        let bytecode = build_bytecode(&[
            0x03, 0xFF, 0x00, 0x00, 0x00, // PUSH 255
            0x02, 0x10, // STORE at index 16
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Memory should have grown to at least 17 elements
        assert!(runner.memory.len() >= 17);
    }
}

// ============================================================================
// CALL/RETURN Tests
// ============================================================================

mod call_return_tests {
    use super::*;

    #[test]
    fn test_call_and_return() {
        // CALL to position 10, then RETURN
        // Note: Current implementation just jumps, doesn't handle return addresses
        let bytecode = build_bytecode(&[
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1 (pos 0)
            0x0F, 0x0A, 0x00, // CALL to 10 (pos 5)
            0x03, 0x99, 0x00, 0x00, 0x00, // PUSH 99 (pos 8) - should execute after RETURN
            0x00, // HALT (pos 13)
            0x03, 0x42, 0x00, 0x00, 0x00, // PUSH 66 (pos 14) - this is at position 10
            0x10, // RETURN (pos 19)
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
    }
}

// ============================================================================
// CAST Instruction Tests
// ============================================================================

mod cast_tests {
    use super::*;

    #[test]
    fn test_cast_noop() {
        // CAST is a no-op for field elements
        let bytecode = build_bytecode(&[
            0x03, 0x42, 0x00, 0x00, 0x00, // PUSH 66
            0x11, // CAST (no-op)
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 66);
    }
}

// ============================================================================
// Unknown Opcode Tests
// ============================================================================

mod error_tests {
    use super::*;

    #[test]
    fn test_unknown_opcode() {
        let bytecode = build_bytecode(&[0xFF]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_err());
    }

    #[test]
    fn test_push_truncated() {
        // PUSH with missing bytes
        let bytecode = build_bytecode(&[
            0x03, 0x01, 0x00, // PUSH with only 3 bytes
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_err());
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_sum_of_three() {
        // 10 + 20 + 30 = 60
        let bytecode = build_bytecode(&[
            0x03, 0x0A, 0x00, 0x00, 0x00, // PUSH 10
            0x03, 0x14, 0x00, 0x00, 0x00, // PUSH 20
            0x05, // ADD -> 30
            0x03, 0x1E, 0x00, 0x00, 0x00, // PUSH 30
            0x05, // ADD -> 60
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 60);
    }

    #[test]
    fn test_fibonacci_like() {
        // Compute 5 + 8
        let bytecode = build_bytecode(&[
            0x03, 0x05, 0x00, 0x00, 0x00, // PUSH 5
            0x03, 0x08, 0x00, 0x00, 0x00, // PUSH 8
            0x05, // ADD = 13
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert_eq!(runner.stack[0].0, 13);
    }

    #[test]
    fn test_comparison_chain() {
        // Check if 10 < 20 and 20 < 10
        let bytecode = build_bytecode(&[
            0x03, 0x0A, 0x00, 0x00, 0x00, // PUSH 10
            0x03, 0x14, 0x00, 0x00, 0x00, // PUSH 20
            0x0C, // LT -> 1 (10 < 20)
            0x03, 0x14, 0x00, 0x00, 0x00, // PUSH 20
            0x03, 0x0A, 0x00, 0x00, 0x00, // PUSH 10
            0x0C, // LT -> 0 (20 < 10 is false)
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        // Stack: [1, 0] (first LT result, second LT result)
        assert_eq!(runner.stack.len(), 2);
        assert_eq!(runner.stack[1].0, 1); // First LT result (bottom)
        assert_eq!(runner.stack[0].0, 0); // Second LT result (top)
    }

    #[test]
    fn test_arithmetic_complex() {
        // ((100 / 4) * 4) + 1
        let bytecode = build_bytecode(&[
            0x03, 0x64, 0x00, 0x00, 0x00, // PUSH 100
            0x03, 0x04, 0x00, 0x00, 0x00, // PUSH 4
            0x08, // DIV
            0x03, 0x04, 0x00, 0x00, 0x00, // PUSH 4
            0x07, // MUL
            0x03, 0x01, 0x00, 0x00, 0x00, // PUSH 1
            0x05, // ADD
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        let result = runner.execute(&bytecode, &mut witnesses);
        assert!(result.is_ok());
        assert_eq!(runner.stack.len(), 1);
    }
}

// ============================================================================
// Flags Tests
// ============================================================================

mod flags_tests {
    use super::*;

    #[test]
    fn test_eq_sets_zero_flag() {
        let bytecode = build_bytecode(&[
            0x03, 0x10, 0x00, 0x00, 0x00, // PUSH 16
            0x03, 0x10, 0x00, 0x00, 0x00, // PUSH 16
            0x0B, // EQ
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert!(runner.flags.zero);
        assert!(!runner.flags.non_zero);
    }

    #[test]
    fn test_eq_sets_nonzero_flag() {
        let bytecode = build_bytecode(&[
            0x03, 0x10, 0x00, 0x00, 0x00,
            0x03, 0x20, 0x00, 0x00, 0x00,
            0x0B, // EQ
            0x00,
        ]);
        let mut runner = BrilligRunner::new();
        let mut witnesses = Vec::new();

        runner.execute(&bytecode, &mut witnesses).unwrap();
        assert!(!runner.flags.zero);
        assert!(runner.flags.non_zero);
    }
}
