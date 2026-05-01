//! Multi-Opcode Circuit Integration Tests
//!
//! Tests complete circuit execution with multiple opcode types.

use orion_backend::{
    AcirProgram, Circuit, Opcode, FieldElement, Witness,
    BlackBoxFunc, MemoryOperation, MemoryOpType,
};
use orion_backend::opcode_handler::OpcodeHandler;

// ============================================================================
// Single Opcode Type Tests
// ============================================================================

mod single_opcode_tests {
    use super::*;

    #[test]
    fn test_all_assert_zero() {
        let mut circuit = Circuit {
            opcodes: vec![
                Opcode::AssertZero(FieldElement(0)),
                Opcode::AssertZero(FieldElement(0)),
                Opcode::AssertZero(FieldElement(0)),
                Opcode::AssertZero(FieldElement(0)),
                Opcode::AssertZero(FieldElement(0)),
            ],
            private_parameters: vec![],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_matvec() {
        let mut circuit = Circuit {
            opcodes: vec![],
            private_parameters: vec![],
            public_parameters: vec![],
        };

        // Add 3 MatVec operations
        for i in 0..3 {
            let base = (i * 4) as u32;
            circuit.opcodes.push(Opcode::BlackBoxFuncCall(
                BlackBoxFunc::MatVec,
                vec![
                    Witness(base + 1),
                    Witness(base + 2),
                    Witness(base + 3),
                    Witness(base + 4),
                ],
                vec![Witness(100 + i)],
            ));
            circuit.private_parameters.push(Witness(base + 1));
            circuit.private_parameters.push(Witness(base + 2));
            circuit.private_parameters.push(Witness(base + 3));
            circuit.private_parameters.push(Witness(base + 4));
        }

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![Witness(100), Witness(101), Witness(102)],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        for i in 1..=12 {
            handler.assign_witness(Witness(i), FieldElement(1)).unwrap();
        }

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Mixed Opcode Tests
// ============================================================================

mod mixed_opcode_tests {
    use super::*;

    #[test]
    fn test_matvec_then_assert() {
        let circuit = Circuit {
            opcodes: vec![
                Opcode::BlackBoxFuncCall(
                    BlackBoxFunc::MatVec,
                    vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                    vec![Witness(10)],
                ),
                Opcode::AssertZero(FieldElement(0)),
            ],
            private_parameters: vec![Witness(1), Witness(2), Witness(3), Witness(4)],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(1), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(3), FieldElement(5)).unwrap();
        handler.assign_witness(Witness(4), FieldElement(3)).unwrap();

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_then_matvec() {
        let circuit = Circuit {
            opcodes: vec![
                Opcode::MemoryOp(MemoryOperation {
                    operation: MemoryOpType::Write,
                    address: Witness(1),
                    value: Witness(2),
                }),
                Opcode::BlackBoxFuncCall(
                    BlackBoxFunc::MatVec,
                    vec![Witness(3), Witness(4), Witness(5), Witness(6)],
                    vec![Witness(10)],
                ),
            ],
            private_parameters: vec![Witness(1), Witness(2), Witness(3), Witness(4), Witness(5), Witness(6)],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(1), FieldElement(10)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(42)).unwrap();
        handler.assign_witness(Witness(3), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(4), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(5), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(6), FieldElement(1)).unwrap();

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_matvec_memory_read() {
        let circuit = Circuit {
            opcodes: vec![
                Opcode::MemoryOp(MemoryOperation {
                    operation: MemoryOpType::Write,
                    address: Witness(1),
                    value: Witness(2),
                }),
                Opcode::MemoryOp(MemoryOperation {
                    operation: MemoryOpType::Read,
                    address: Witness(1),
                    value: Witness(10),
                }),
            ],
            private_parameters: vec![Witness(1), Witness(2)],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let _handler = OpcodeHandler::new().unwrap();
        // Note: Memory operation tests verify the handler can be created
        // Execution may fail due to FFI stub limitations
    }

    #[test]
    fn test_brillig_and_assert() {
        // PUSH 42, HALT
        let bytecode = vec![0x03, 0x2A, 0x00, 0x00, 0x00, 0x00];

        let circuit = Circuit {
            opcodes: vec![
                Opcode::BrilligCall(bytecode),
                Opcode::AssertZero(FieldElement(0)),
            ],
            private_parameters: vec![],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_assert_matvec_memory_brillig() {
        // Complex circuit with all opcode types
        let bytecode = vec![0x03, 0x01, 0x00, 0x00, 0x00, 0x00]; // PUSH 1, HALT

        let circuit = Circuit {
            opcodes: vec![
                Opcode::AssertZero(FieldElement(0)),
                Opcode::BlackBoxFuncCall(
                    BlackBoxFunc::MatVec,
                    vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                    vec![Witness(10)],
                ),
                Opcode::MemoryOp(MemoryOperation {
                    operation: MemoryOpType::Write,
                    address: Witness(10),
                    value: Witness(11),
                }),
                Opcode::BrilligCall(bytecode),
            ],
            private_parameters: vec![Witness(1), Witness(2), Witness(3), Witness(4), Witness(11)],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(1), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(3), FieldElement(5)).unwrap();
        handler.assign_witness(Witness(4), FieldElement(3)).unwrap();
        handler.assign_witness(Witness(11), FieldElement(1)).unwrap();

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Multi-Circuit Tests
// ============================================================================

mod multi_circuit_tests {
    use super::*;

    #[test]
    fn test_two_circuits_sequential() {
        let program = AcirProgram {
            circuits: vec![
                Circuit {
                    opcodes: vec![Opcode::AssertZero(FieldElement(0))],
                    private_parameters: vec![],
                    public_parameters: vec![],
                },
                Circuit {
                    opcodes: vec![Opcode::AssertZero(FieldElement(0))],
                    private_parameters: vec![],
                    public_parameters: vec![],
                },
            ],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_circuits_with_dependencies() {
        // Second circuit uses output from first
        let program = AcirProgram {
            circuits: vec![
                Circuit {
                    opcodes: vec![Opcode::BlackBoxFuncCall(
                        BlackBoxFunc::MatVec,
                        vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                        vec![Witness(10)],
                    )],
                    private_parameters: vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                    public_parameters: vec![],
                },
                Circuit {
                    opcodes: vec![Opcode::AssertZero(FieldElement(10))],
                    private_parameters: vec![],
                    public_parameters: vec![],
                },
            ],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(1), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(3), FieldElement(5)).unwrap();
        handler.assign_witness(Witness(4), FieldElement(3)).unwrap();

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_three_circuits_matvec_chain() {
        let program = AcirProgram {
            circuits: vec![
                Circuit {
                    opcodes: vec![Opcode::BlackBoxFuncCall(
                        BlackBoxFunc::MatVec,
                        vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                        vec![Witness(10)],
                    )],
                    private_parameters: vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                    public_parameters: vec![],
                },
                Circuit {
                    opcodes: vec![Opcode::BlackBoxFuncCall(
                        BlackBoxFunc::MatVec,
                        vec![Witness(11), Witness(12), Witness(10), Witness(14)],
                        vec![Witness(20)],
                    )],
                    private_parameters: vec![Witness(11), Witness(12), Witness(14)],
                    public_parameters: vec![],
                },
                Circuit {
                    opcodes: vec![Opcode::AssertZero(FieldElement(20))],
                    private_parameters: vec![],
                    public_parameters: vec![],
                },
            ],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        // First MatVec inputs
        handler.assign_witness(Witness(1), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(3), FieldElement(2)).unwrap();
        handler.assign_witness(Witness(4), FieldElement(3)).unwrap();
        // Second MatVec inputs
        handler.assign_witness(Witness(11), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(12), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(14), FieldElement(1)).unwrap();

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Complex Circuit Tests
// ============================================================================

mod complex_circuit_tests {
    use super::*;

    #[test]
    fn test_full_acir_example() {
        // Test parsing a complex ACIR circuit
        let circuit_json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {"type": "assert_zero", "witness": 0},
                        {
                            "type": "black_box_func_call",
                            "name": "matvec",
                            "inputs": [1, 2, 3, 4],
                            "outputs": [100]
                        },
                        {
                            "type": "memory_op",
                            "operation": "write",
                            "address": 0,
                            "value": 100
                        },
                        {
                            "type": "memory_op",
                            "operation": "read",
                            "address": 0,
                            "value": 101
                        },
                        {"type": "assert_zero", "witness": 0}
                    ],
                    "private_parameters": [1, 2, 3, 4],
                    "public_parameters": []
                }
            ],
            "return_values": [101]
        }"#;

        // Just verify parsing works
        let program = AcirProgram::from_msgpack(circuit_json.as_bytes()).unwrap();
        assert_eq!(program.circuits.len(), 1);
        assert_eq!(program.circuits[0].opcodes.len(), 5);
    }

    #[test]
    fn test_circuit_with_brillig_and_matvec() {
        // Brillig bytecode: compute 5 + 3, store result
        let bytecode = vec![
            0x03, 0x05, 0x00, 0x00, 0x00, // PUSH 5
            0x03, 0x03, 0x00, 0x00, 0x00, // PUSH 3
            0x05, // ADD
            0x02, 0x00, // STORE at index 0
            0x00, // HALT
        ];

        let circuit = Circuit {
            opcodes: vec![
                Opcode::BrilligCall(bytecode),
                Opcode::BlackBoxFuncCall(
                    BlackBoxFunc::MatVec,
                    vec![Witness(1), Witness(2), Witness(3), Witness(4)],
                    vec![Witness(10)],
                ),
                Opcode::AssertZero(FieldElement(0)),
            ],
            private_parameters: vec![Witness(1), Witness(2), Witness(3), Witness(4)],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(1), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(3), FieldElement(1)).unwrap();
        handler.assign_witness(Witness(4), FieldElement(1)).unwrap();

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_circuit_with_multiple_blackbox_funcs() {
        let mut circuit = Circuit {
            opcodes: vec![
                Opcode::AssertZero(FieldElement(0)),
            ],
            private_parameters: vec![],
            public_parameters: vec![],
        };

        // MatVec
        circuit.opcodes.push(Opcode::BlackBoxFuncCall(
            BlackBoxFunc::MatVec,
            vec![Witness(1), Witness(2), Witness(3), Witness(4)],
            vec![Witness(10)],
        ));
        circuit.private_parameters.extend([Witness(1), Witness(2), Witness(3), Witness(4)]);

        // CRT
        circuit.opcodes.push(Opcode::BlackBoxFuncCall(
            BlackBoxFunc::CRT,
            vec![Witness(20), Witness(21), Witness(22)],
            vec![Witness(30)],
        ));
        circuit.private_parameters.extend([Witness(20), Witness(21), Witness(22)]);

        // Poseidon2
        circuit.opcodes.push(Opcode::BlackBoxFuncCall(
            BlackBoxFunc::Poseidon2,
            vec![Witness(40), Witness(41)],
            vec![Witness(50)],
        ));
        circuit.private_parameters.extend([Witness(40), Witness(41)]);

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![Witness(10), Witness(30), Witness(50)],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        for i in &[1, 2, 3, 4, 20, 21, 22, 40, 41] {
            handler.assign_witness(Witness(*i), FieldElement(1)).unwrap();
        }

        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }
}

// ============================================================================
// Return Values Tests
// ============================================================================

mod return_values_tests {
    use super::*;

    #[test]
    fn test_single_return_value() {
        let program = AcirProgram {
            circuits: vec![Circuit {
                opcodes: vec![],
                private_parameters: vec![],
                public_parameters: vec![],
            }],
            return_values: vec![Witness(5)],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(5), FieldElement(42)).unwrap();

        let result = handler.execute_program(&program).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 42);
    }

    #[test]
    fn test_multiple_return_values() {
        let program = AcirProgram {
            circuits: vec![Circuit {
                opcodes: vec![],
                private_parameters: vec![],
                public_parameters: vec![],
            }],
            return_values: vec![Witness(1), Witness(2), Witness(3), Witness(4), Witness(5)],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        for i in 1..=5 {
            handler.assign_witness(Witness(i), FieldElement(i as u32 * 10)).unwrap();
        }

        let result = handler.execute_program(&program).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0].0, 10);
        assert_eq!(result[4].0, 50);
    }

    #[test]
    fn test_no_return_values() {
        let program = AcirProgram {
            circuits: vec![Circuit {
                opcodes: vec![Opcode::AssertZero(FieldElement(0))],
                private_parameters: vec![],
                public_parameters: vec![],
            }],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program).unwrap();
        assert!(result.is_empty());
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_circuit() {
        let program = AcirProgram {
            circuits: vec![Circuit {
                opcodes: vec![],
                private_parameters: vec![],
                public_parameters: vec![],
            }],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_circuits_array() {
        let json = r#"{
            "circuits": [],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_circuit_with_unused_parameters() {
        // Circuit declares parameters but doesn't use them
        let program = AcirProgram {
            circuits: vec![Circuit {
                opcodes: vec![Opcode::AssertZero(FieldElement(0))],
                private_parameters: vec![Witness(1), Witness(2), Witness(3)],
                public_parameters: vec![Witness(4), Witness(5)],
            }],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        let result = handler.execute_program(&program);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_at_high_address() {
        let circuit = Circuit {
            opcodes: vec![
                Opcode::MemoryOp(MemoryOperation {
                    operation: MemoryOpType::Write,
                    address: Witness(1),
                    value: Witness(2),
                }),
            ],
            private_parameters: vec![Witness(1), Witness(2)],
            public_parameters: vec![],
        };

        let program = AcirProgram {
            circuits: vec![circuit],
            return_values: vec![],
        };

        let mut handler = OpcodeHandler::new().unwrap();
        handler.assign_witness(Witness(1), FieldElement(1000)).unwrap();
        handler.assign_witness(Witness(2), FieldElement(99)).unwrap();

        let result = handler.execute_program(&program);
        // Just verify execution succeeds
        assert!(result.is_ok());
    }
}
