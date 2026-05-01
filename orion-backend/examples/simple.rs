//! Orion Backend CLI
//!
//! Example CLI for using the Orion backend to process ACIR circuits.

use std::fs;
use std::path::Path;
use orion_backend::{AcirProgram, opcode_handler::OpcodeHandler};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Orion Backend for Noir ACIR");
        println!();
        println!("Usage:");
        println!("  orion-backend <acir_file>    Process ACIR file");
        println!("  orion-backend --info          Show backend info");
        println!();
        println!("Example:");
        println!("  orion-backend circuit.acir");
        return;
    }

    if args[1] == "--info" {
        println!("Orion Backend v0.1.0");
        println!();
        println!("Backend: Orion");
        println!("Hardware acceleration:");
        println!("  - ANE: Apple Neural Engine (MatVec)");
        println!("  - GPU: Metal GPU (NTT)");
        println!();
        println!("Supported opcodes:");
        println!("  - AssertZero");
        println!("  - BlackBoxFuncCall (MatVec, NTT, CRT, Poseidon2)");
        println!("  - MemoryOp");
        println!("  - BrilligCall");
        println!("  - Call");
        return;
    }

    let acir_path = Path::new(&args[1]);
    if !acir_path.exists() {
        eprintln!("Error: File not found: {}", acir_path.display());
        std::process::exit(1);
    }

    println!("Loading ACIR from: {}", acir_path.display());

    let data = fs::read(acir_path).expect("Failed to read ACIR file");
    let program = match AcirProgram::from_msgpack(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing ACIR: {}", e);
            std::process::exit(1);
        }
    };

    println!("Parsed ACIR program:");
    println!("  Circuits: {}", program.circuits.len());
    for (i, circuit) in program.circuits.iter().enumerate() {
        println!("    Circuit {}: {} opcodes", i, circuit.opcodes.len());
    }
    println!("  Return values: {}", program.return_values.len());

    println!();
    println!("Executing circuit...");

    let mut handler = OpcodeHandler::new().expect("Failed to create opcode handler");
    match handler.execute_program(&program) {
        Ok(results) => {
            println!("Execution successful!");
            println!("Return values: {:?}", results);
        }
        Err(e) => {
            eprintln!("Execution error: {}", e);
            std::process::exit(1);
        }
    }
}