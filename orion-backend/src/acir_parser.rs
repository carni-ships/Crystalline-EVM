//! ACIR Deserialization (msgpack-compact format)
//!
//! Noir compiler emits ACIR in msgpack-compact binary format.
//! This module handles parsing that format into our internal types.

use super::{AcirProgram, Circuit, Opcode, FieldElement, Witness, BlackBoxFunc, MemoryOperation, MemoryOpType};
use super::error::BackendError;

/// Parse msgpack-compact ACIR format
pub fn parse_msgpack(data: &[u8]) -> Result<AcirProgram, BackendError> {
    // Msgpack format: [version, circuits_array, return_values]
    // For now, implement a simplified parser

    if data.is_empty() {
        return Err(BackendError::ParseError("Empty data".to_string()));
    }

    // Try to parse as JSON first (common debug format)
    if data[0] == b'{' || data[0] == b'[' {
        return parse_json(data);
    }

    // For binary msgpack, we'd use a msgpack crate
    // For now, return error indicating format need
    Err(BackendError::ParseError(
        "Unsupported format - expected JSON ACIR".to_string(),
    ))
}

/// Parse JSON ACIR format (common in development/debug)
fn parse_json(data: &[u8]) -> Result<AcirProgram, BackendError> {
    let json: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| BackendError::ParseError(format!("JSON parse error: {}", e)))?;

    let mut circuits = Vec::new();

    // Handle both single circuit and array of circuits
    match &json {
        serde_json::Value::Object(map) => {
            if let Some(circuits_val) = map.get("circuits") {
                parse_circuits_array(circuits_val, &mut circuits)?;
            } else {
                // Single circuit object
                circuits.push(parse_circuit_object(map)?);
            }
        }
        serde_json::Value::Array(arr) => {
            // Handle array of circuits directly
            for circuit_val in arr {
                let circuit_obj = circuit_val.as_object()
                    .ok_or_else(|| BackendError::ParseError("circuit must be object".to_string()))?;
                circuits.push(parse_circuit_object(circuit_obj)?);
            }
        }
        _ => return Err(BackendError::ParseError("Invalid ACIR structure".to_string())),
    }

    let return_values = json.get("return_values")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|n| Witness(n as u32))
                .collect()
        })
        .unwrap_or_default();

    Ok(AcirProgram { circuits, return_values })
}

fn parse_circuits_array(value: &serde_json::Value, circuits: &mut Vec<Circuit>) -> Result<(), BackendError> {
    let arr = value.as_array()
        .ok_or_else(|| BackendError::ParseError("circuits must be array".to_string()))?;

    for circuit_val in arr {
        let circuit_obj = circuit_val.as_object()
            .ok_or_else(|| BackendError::ParseError("circuit must be object".to_string()))?;
        circuits.push(parse_circuit_object(circuit_obj)?);
    }
    Ok(())
}

fn parse_circuit_object(obj: &serde_json::Map<String, serde_json::Value>) -> Result<Circuit, BackendError> {
    let opcodes = obj.get("opcodes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| parse_opcode(v))
                .collect()
        })
        .unwrap_or_default();

    let private_parameters = obj.get("private_parameters")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|n| Witness(n as u32))
                .collect()
        })
        .unwrap_or_default();

    let public_parameters = obj.get("public_parameters")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|n| Witness(n as u32))
                .collect()
        })
        .unwrap_or_default();

    Ok(Circuit { opcodes, private_parameters, public_parameters })
}

fn parse_opcode(value: &serde_json::Value) -> Option<Opcode> {
    let obj = value.as_object()?;
    let opcode_type = obj.get("type")?.as_str()?;

    match opcode_type {
        "assert_zero" => {
            let witness = obj.get("witness")?.as_u64()? as u32;
            Some(Opcode::AssertZero(FieldElement(witness)))
        }
        "black_box_func_call" => {
            let func_name = obj.get("name")?.as_str()?;
            let func = match func_name {
                "matvec" | "MATVEC" | "LATTICE_MATVEC" => BlackBoxFunc::MatVec,
                "ntt" | "NTT" | "LATTICE_NTT" => BlackBoxFunc::NTT,
                "crt" | "CRT" | "LATTICE_CRT" => BlackBoxFunc::CRT,
                "poseidon2" | "POSEIDON2" => BlackBoxFunc::Poseidon2,
                "permutation_check" | "PERMUTATION_CHECK" => BlackBoxFunc::PermutationCheck,
                "keccak256" => BlackBoxFunc::Keccak256,
                "sha256" => BlackBoxFunc::SHA256,
                "ecdsa_verify" => BlackBoxFunc::ECDSAVerify,
                "schnorr_verify" => BlackBoxFunc::SchnorrVerify,
                _ => return None,
            };

            let inputs = obj.get("inputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|n| Witness(n as u32))
                        .collect()
                })
                .unwrap_or_default();

            let outputs = obj.get("outputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|n| Witness(n as u32))
                        .collect()
                })
                .unwrap_or_default();

            Some(Opcode::BlackBoxFuncCall(func, inputs, outputs))
        }
        "memory_op" => {
            let op = obj.get("operation")?.as_str()?;
            let op_type = match op {
                "write" => MemoryOpType::Write,
                "read" => MemoryOpType::Read,
                _ => return None,
            };
            let address = obj.get("address")?.as_u64()? as u32;
            let value = obj.get("value")?.as_u64()? as u32;
            Some(Opcode::MemoryOp(MemoryOperation {
                operation: op_type,
                address: Witness(address),
                value: Witness(value),
            }))
        }
        "brillig_call" => {
            let bytecode = obj.get("bytecode")?.as_array()?;
            let bytes: Vec<u8> = bytecode
                .iter()
                .filter_map(|v| v.as_u64())
                .map(|n| n as u8)
                .collect();
            Some(Opcode::BrilligCall(bytes))
        }
        "call" => {
            let function = obj.get("function")?.as_str()?.to_string();
            let args = obj.get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|n| Witness(n as u32))
                        .collect()
                })
                .unwrap_or_default();
            Some(Opcode::Call { function, args })
        }
        _ => None,
    }
}

/// Serialize ACIR program to JSON (for debugging)
pub fn to_json(program: &AcirProgram) -> Result<String, BackendError> {
    let mut circuits_arr = Vec::new();
    for circuit in &program.circuits {
        let mut obj = serde_json::Map::new();

        let mut opcodes_arr = Vec::new();
        for opcode in &circuit.opcodes {
            opcodes_arr.push(opcode_to_json(opcode)?);
        }
        obj.insert("opcodes".to_string(), serde_json::Value::Array(opcodes_arr));

        obj.insert("private_parameters".to_string(), serde_json::json!(
            circuit.private_parameters.iter().map(|w| w.0).collect::<Vec<_>>()
        ));
        obj.insert("public_parameters".to_string(), serde_json::json!(
            circuit.public_parameters.iter().map(|w| w.0).collect::<Vec<_>>()
        ));

        circuits_arr.push(serde_json::Value::Object(obj));
    }

    let mut root = serde_json::Map::new();
    root.insert("circuits".to_string(), serde_json::Value::Array(circuits_arr));
    root.insert("return_values".to_string(), serde_json::json!(
        program.return_values.iter().map(|w| w.0).collect::<Vec<_>>()
    ));

    serde_json::to_string_pretty(&serde_json::Value::Object(root))
        .map_err(|e| BackendError::SerializationError(e.to_string()))
}

fn opcode_to_json(opcode: &Opcode) -> Result<serde_json::Value, BackendError> {
    match opcode {
        Opcode::AssertZero(fe) => Ok(serde_json::json!({
            "type": "assert_zero",
            "witness": fe.0
        })),
        Opcode::BlackBoxFuncCall(func, inputs, outputs) => {
            let func_name = match func {
                BlackBoxFunc::MatVec => "matvec",
                BlackBoxFunc::NTT => "ntt",
                BlackBoxFunc::CRT => "crt",
                BlackBoxFunc::Poseidon2 => "poseidon2",
                BlackBoxFunc::PermutationCheck => "permutation_check",
                BlackBoxFunc::Keccak256 => "keccak256",
                BlackBoxFunc::SHA256 => "sha256",
                BlackBoxFunc::ECDSAVerify => "ecdsa_verify",
                BlackBoxFunc::SchnorrVerify => "schnorr_verify",
            };
            Ok(serde_json::json!({
                "type": "black_box_func_call",
                "name": func_name,
                "inputs": inputs.iter().map(|w| w.0).collect::<Vec<_>>(),
                "outputs": outputs.iter().map(|w| w.0).collect::<Vec<_>>()
            }))
        }
        Opcode::MemoryOp(op) => {
            let op_str = match op.operation {
                MemoryOpType::Write => "write",
                MemoryOpType::Read => "read",
            };
            Ok(serde_json::json!({
                "type": "memory_op",
                "operation": op_str,
                "address": op.address.0,
                "value": op.value.0
            }))
        }
        Opcode::BrilligCall(bytecode) => Ok(serde_json::json!({
            "type": "brillig_call",
            "bytecode": bytecode
        })),
        Opcode::Call { function, args } => Ok(serde_json::json!({
            "type": "call",
            "function": function,
            "args": args.iter().map(|w| w.0).collect::<Vec<_>>()
        })),
    }
}