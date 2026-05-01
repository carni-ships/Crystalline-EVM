//! Unit tests for ACIR parser
//!
//! Tests parsing of various ACIR formats including JSON and msgpack-compact.

use orion_backend::*;

// ============================================================================
// JSON Format Parsing Tests
// ============================================================================

mod json_format {
    use super::*;

    #[test]
    fn test_parse_empty_circuit() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        assert_eq!(program.circuits.len(), 1);
        assert_eq!(program.circuits[0].opcodes.len(), 0);
        assert!(program.return_values.is_empty());
    }

    #[test]
    fn test_parse_single_assert_zero() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {"type": "assert_zero", "witness": 42}
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [42]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        assert_eq!(program.circuits.len(), 1);
        assert_eq!(program.circuits[0].opcodes.len(), 1);

        if let Opcode::AssertZero(fe) = &program.circuits[0].opcodes[0] {
            assert_eq!(fe.0, 42);
        } else {
            panic!("Expected AssertZero opcode");
        }

        assert_eq!(program.return_values.len(), 1);
        assert_eq!(program.return_values[0].0, 42);
    }

    #[test]
    fn test_parse_matvec_black_box() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "black_box_func_call",
                            "name": "matvec",
                            "inputs": [1, 2, 3, 4],
                            "outputs": [5, 6]
                        }
                    ],
                    "private_parameters": [1, 2],
                    "public_parameters": [3, 4]
                }
            ],
            "return_values": [5, 6]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        assert_eq!(program.circuits.len(), 1);

        if let Opcode::BlackBoxFuncCall(func, inputs, outputs) = &program.circuits[0].opcodes[0] {
            assert_eq!(*func, BlackBoxFunc::MatVec);
            assert_eq!(inputs.len(), 4);
            assert_eq!(outputs.len(), 2);
        } else {
            panic!("Expected BlackBoxFuncCall opcode");
        }
    }

    #[test]
    fn test_parse_ntt_black_box() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "black_box_func_call",
                            "name": "ntt",
                            "inputs": [1],
                            "outputs": [2]
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [2]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::BlackBoxFuncCall(func, _, _) = &program.circuits[0].opcodes[0] {
            assert_eq!(*func, BlackBoxFunc::NTT);
        } else {
            panic!("Expected BlackBoxFuncCall opcode");
        }
    }

    #[test]
    fn test_parse_crt_black_box() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "black_box_func_call",
                            "name": "crt",
                            "inputs": [1, 2, 3],
                            "outputs": [4]
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [4]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::BlackBoxFuncCall(func, _, _) = &program.circuits[0].opcodes[0] {
            assert_eq!(*func, BlackBoxFunc::CRT);
        } else {
            panic!("Expected BlackBoxFuncCall opcode");
        }
    }

    #[test]
    fn test_parse_poseidon2_black_box() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "black_box_func_call",
                            "name": "poseidon2",
                            "inputs": [1, 2, 3, 4],
                            "outputs": [5]
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [5]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::BlackBoxFuncCall(func, _, _) = &program.circuits[0].opcodes[0] {
            assert_eq!(*func, BlackBoxFunc::Poseidon2);
        } else {
            panic!("Expected BlackBoxFuncCall opcode");
        }
    }

    #[test]
    fn test_parse_memory_write() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "memory_op",
                            "operation": "write",
                            "address": 10,
                            "value": 42
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::MemoryOp(op) = &program.circuits[0].opcodes[0] {
            assert_eq!(op.operation, MemoryOpType::Write);
            assert_eq!(op.address.0, 10);
            assert_eq!(op.value.0, 42);
        } else {
            panic!("Expected MemoryOp opcode");
        }
    }

    #[test]
    fn test_parse_memory_read() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "memory_op",
                            "operation": "read",
                            "address": 5,
                            "value": 15
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [15]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::MemoryOp(op) = &program.circuits[0].opcodes[0] {
            assert_eq!(op.operation, MemoryOpType::Read);
            assert_eq!(op.address.0, 5);
            assert_eq!(op.value.0, 15);
        } else {
            panic!("Expected MemoryOp opcode");
        }
    }

    #[test]
    fn test_parse_brillig_call() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "brillig_call",
                            "bytecode": [1, 2, 3, 4, 5]
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::BrilligCall(bytecode) = &program.circuits[0].opcodes[0] {
            assert_eq!(bytecode, &vec![1, 2, 3, 4, 5]);
        } else {
            panic!("Expected BrilligCall opcode");
        }
    }

    #[test]
    fn test_parse_call() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "call",
                            "function": "test_function",
                            "args": [1, 2, 3]
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();

        if let Opcode::Call { function, args } = &program.circuits[0].opcodes[0] {
            assert_eq!(function, "test_function");
            assert_eq!(args.len(), 3);
            assert_eq!(args[0].0, 1);
            assert_eq!(args[1].0, 2);
            assert_eq!(args[2].0, 3);
        } else {
            panic!("Expected Call opcode");
        }
    }

    #[test]
    fn test_parse_multiple_opcodes() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {"type": "assert_zero", "witness": 1},
                        {"type": "assert_zero", "witness": 2},
                        {"type": "assert_zero", "witness": 3}
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [1, 2, 3]
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        assert_eq!(program.circuits[0].opcodes.len(), 3);
    }

    #[test]
    fn test_parse_multiple_circuits() {
        let json = r#"[
            {
                "opcodes": [{"type": "assert_zero", "witness": 1}],
                "private_parameters": [],
                "public_parameters": []
            },
            {
                "opcodes": [{"type": "assert_zero", "witness": 2}],
                "private_parameters": [],
                "public_parameters": []
            }
        ]"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        assert_eq!(program.circuits.len(), 2);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling {
    use super::*;

    #[test]
    fn test_parse_empty_data() {
        let result = AcirProgram::from_msgpack(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_json() {
        let invalid_json = b"not valid json at all {{{";
        let result = AcirProgram::from_msgpack(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_structure() {
        // Valid JSON but not ACIR structure
        let invalid = r#"{"not": "acir"}"#;
        let result = AcirProgram::from_msgpack(invalid.as_bytes());
        // This should either error or produce empty circuits
        // The parser handles missing "circuits" key by returning empty
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_unknown_opcode_type() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {"type": "unknown_opcode", "data": 123}
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        // Unknown opcodes are skipped
        assert_eq!(program.circuits[0].opcodes.len(), 0);
    }

    #[test]
    fn test_parse_missing_opcode_fields() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {"type": "assert_zero"}
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        // Missing fields result in skipped opcodes
        assert_eq!(program.circuits[0].opcodes.len(), 0);
    }
}

// ============================================================================
// Serialization Tests
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_roundtrip_assert_zero() {
        let original = r#"{
            "circuits": [
                {
                    "opcodes": [{"type": "assert_zero", "witness": 42}],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [42]
        }"#;

        let program = AcirProgram::from_msgpack(original.as_bytes()).unwrap();
        let json_str = acir_parser::to_json(&program).unwrap();
        let reparsed = AcirProgram::from_msgpack(json_str.as_bytes()).unwrap();

        assert_eq!(program.circuits.len(), reparsed.circuits.len());
    }

    #[test]
    fn test_roundtrip_blackbox() {
        let original = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "black_box_func_call",
                            "name": "matvec",
                            "inputs": [1, 2],
                            "outputs": [3]
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": [3]
        }"#;

        let program = AcirProgram::from_msgpack(original.as_bytes()).unwrap();
        let json_str = acir_parser::to_json(&program).unwrap();
        let reparsed = AcirProgram::from_msgpack(json_str.as_bytes()).unwrap();

        if let (
            Opcode::BlackBoxFuncCall(f1, _, _),
            Opcode::BlackBoxFuncCall(f2, _, _),
        ) = (
            &program.circuits[0].opcodes[0],
            &reparsed.circuits[0].opcodes[0],
        ) {
            assert_eq!(*f1, *f2);
        } else {
            panic!("Expected BlackBoxFuncCall");
        }
    }

    #[test]
    fn test_roundtrip_memory_op() {
        let json = r#"{
            "circuits": [
                {
                    "opcodes": [
                        {
                            "type": "memory_op",
                            "operation": "write",
                            "address": 10,
                            "value": 42
                        }
                    ],
                    "private_parameters": [],
                    "public_parameters": []
                }
            ],
            "return_values": []
        }"#;

        let program = AcirProgram::from_msgpack(json.as_bytes()).unwrap();
        let json_str = acir_parser::to_json(&program).unwrap();
        let reparsed = AcirProgram::from_msgpack(json_str.as_bytes()).unwrap();

        assert_eq!(program.circuits.len(), reparsed.circuits.len());
        assert_eq!(program.circuits[0].opcodes.len(), reparsed.circuits[0].opcodes.len());
    }
}

// ============================================================================
// Field Element and Witness Tests
// ============================================================================

mod field_element_tests {
    use super::*;

    #[test]
    fn test_field_element_new() {
        let fe = FieldElement::new(100);
        assert_eq!(fe.0, 100);
    }

    #[test]
    fn test_field_element_modulo() {
        // Test that values are modded by Dilithium-3 modulus
        let fe = FieldElement::new(8383489); // Should wrap to 0
        assert_eq!(fe.0, 0);

        let fe = FieldElement::new(8383490); // Should wrap to 1
        assert_eq!(fe.0, 1);
    }

    #[test]
    fn test_field_element_default() {
        let fe = FieldElement::default();
        assert_eq!(fe.0, 0);
    }

    #[test]
    fn test_witness_default() {
        let w = Witness::default();
        assert_eq!(w.0, 0);
    }

    #[test]
    fn test_witness_copy() {
        let w1 = Witness(42);
        let w2 = w1; // Should copy
        assert_eq!(w1.0, w2.0);
    }
}

// ============================================================================
// Black Box Function Tests
// ============================================================================

mod black_box_func_tests {
    use super::*;

    #[test]
    fn test_matvec_uses_ane() {
        assert!(BlackBoxFunc::MatVec.uses_ane());
        assert!(!BlackBoxFunc::MatVec.uses_gpu());
    }

    #[test]
    fn test_ntt_uses_gpu() {
        assert!(!BlackBoxFunc::NTT.uses_ane());
        assert!(BlackBoxFunc::NTT.uses_gpu());
    }

    #[test]
    fn test_crt_no_acceleration() {
        assert!(!BlackBoxFunc::CRT.uses_ane());
        assert!(!BlackBoxFunc::CRT.uses_gpu());
    }

    #[test]
    fn test_poseidon2_no_acceleration() {
        assert!(!BlackBoxFunc::Poseidon2.uses_ane());
        assert!(!BlackBoxFunc::Poseidon2.uses_gpu());
    }

    #[test]
    fn test_hash_functions_no_acceleration() {
        assert!(!BlackBoxFunc::Keccak256.uses_ane());
        assert!(!BlackBoxFunc::SHA256.uses_ane());
        assert!(!BlackBoxFunc::ECDSAVerify.uses_ane());
        assert!(!BlackBoxFunc::SchnorrVerify.uses_ane());
    }
}
