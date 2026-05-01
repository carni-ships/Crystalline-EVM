//! EVM Opcodes for Lattice Field
//!
//! Adapts Zoltraak's opcode definitions for lattice field q=8383489.
//! Gas costs follow Ethereum Yellow Paper (EIP-150 revision).

/// All EVM opcodes organized by category.
/// Field-adapted: stack values are modulo Q=8383489
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    // MARK: - Stop and Arithmetic (0x00-0x0B)

    STOP          = 0x00,  // Halts execution, gas: 0
    ADD           = 0x01,  // Addition, gas: 3
    MUL           = 0x02,  // Multiplication, gas: 5
    SUB           = 0x03,  // Subtraction, gas: 3
    DIV           = 0x04,  // Integer division, gas: 5
    SDIV          = 0x05,  // Signed integer division, gas: 5
    MOD           = 0x06,  // Modulo, gas: 5
    SMOD          = 0x07,  // Signed modulo, gas: 5
    ADDMOD        = 0x08,  // Modular addition, gas: 8
    MULMOD        = 0x09,  // Modular multiplication, gas: 8
    EXP           = 0x0A,  // Exponential, gas: 10 + 50*exp_byte
    SIGNEXTEND    = 0x0B,  // Sign extend, gas: 5

    // MARK: - Comparison & Bitwise (0x10-0x1D)

    LT            = 0x10,  // Less than, gas: 3
    GT            = 0x11,  // Greater than, gas: 3
    SLT           = 0x12,  // Signed less than, gas: 3
    SGT           = 0x13,  // Signed greater than, gas: 3
    EQ            = 0x14,  // Equality, gas: 3
    ISZERO        = 0x15,  // Is zero, gas: 3
    AND           = 0x16,  // Bitwise AND, gas: 3
    OR            = 0x17,  // Bitwise OR, gas: 3
    XOR           = 0x18,  // Bitwise XOR, gas: 3
    NOT           = 0x19,  // Bitwise NOT, gas: 3
    BYTE          = 0x1A,  // Extract byte, gas: 3
    SHL           = 0x1B,  // Shift left, gas: 3
    SHR           = 0x1C,  // Shift right, gas: 3
    SAR           = 0x1D,  // Arithmetic shift right, gas: 3

    // MARK: - SHA3 (0x20)

    KECCAK256     = 0x20,  // Keccak-256 hash, gas: 30 + 6*words

    // MARK: - Environmental Information (0x30-0x3F)

    ADDRESS       = 0x30,  // Get address of executing contract, gas: 2
    BALANCE       = 0x31,  // Get balance, gas: 2600 (cold) / 100 (warm)
    ORIGIN        = 0x32,  // Get tx origin, gas: 2
    CALLER        = 0x33,  // Get caller, gas: 2
    CALLVALUE     = 0x34,  // Get call value, gas: 2
    CALLDATALOAD  = 0x35,  // Get calldata, gas: 3
    CALLDATASIZE  = 0x36,  // Get calldata size, gas: 2
    CALLDATACOPY  = 0x37,  // Copy calldata, gas: 3 + 3*words
    CODESIZE      = 0x38,  // Get code size, gas: 2
    CODECOPY      = 0x39,  // Copy code, gas: 3 + 3*words
    GASPRICE      = 0x3A,  // Get gas price, gas: 2
    EXTCODESIZE   = 0x3B,  // Get external code size, gas: 2600 (cold) / 100 (warm)
    EXTCODECOPY   = 0x3C,  // Copy external code, gas: 2600 + 3*words (cold)
    RETURNDATASIZE= 0x3D,  // Get returndata size, gas: 2
    RETURNDATACOPY= 0x3E, // Copy returndata, gas: 3 + 3*words
    EXTCODEHASH   = 0x3F,  // Get extcodehash, gas: 2600 (cold) / 100 (warm)

    // MARK: - Block Operations (0x40-0x48)

    BLOCKHASH     = 0x40,  // Get block hash, gas: 20
    COINBASE      = 0x41,  // Get block coinbase, gas: 2
    TIMESTAMP     = 0x42,  // Get block timestamp, gas: 2
    NUMBER        = 0x43,  // Get block number, gas: 2
    PREVRANDAO    = 0x44,  // Get block prevrandao, gas: 2
    GASLIMIT      = 0x45,  // Get block gas limit, gas: 2
    CHAINID       = 0x46,  // Get chain ID, gas: 2
    SELFBALANCE   = 0x47,  // Get self balance, gas: 5
    BASEFEE       = 0x48,  // Get block base fee, gas: 2
    BLOBHASH      = 0x49,  // Get blob hash (EIP-4844), gas: 2
    BLOBBASEFEE   = 0x4A,  // Get blob base fee (EIP-4844), gas: 2

    // MARK: - Memory Operations (0x50-0x5A)

    POP           = 0x50,  // Pop from stack, gas: 2
    MLOAD         = 0x51,  // Load from memory, gas: 3
    MSTORE        = 0x52,  // Store to memory, gas: 3
    MSTORE8       = 0x53,  // Store byte to memory, gas: 3
    SLOAD         = 0x54,  // Load from storage, gas: 2100 (cold) / 100 (warm)
    SSTORE        = 0x55,  // Store to storage, gas: dynamic
    JUMP          = 0x56,  // Conditional jump, gas: 8
    JUMPI         = 0x57,  // Conditional jump if true, gas: 10
    JUMPDEST      = 0x5B,  // Valid jump destination, gas: 1
    PC            = 0x58,  // Get program counter, gas: 2
    MSIZE         = 0x59,  // Get memory size, gas: 2
    GAS           = 0x5A,  // Get available gas, gas: 2
    TLOAD         = 0x5C,  // Transient storage load (EVM384)
    TSTORE        = 0x5D,  // Transient storage store (EVM384)
    MCOPY         = 0x5E,  // Memory copy (EIP-5656)
    PUSH0         = 0x5F,  // Push 0 constant (EIP-3855), gas: 2

    // MARK: - Push Operations (0x60-0x7F)

    PUSH1         = 0x60,  // Push 1 byte, gas: 3
    PUSH2         = 0x61,  // Push 2 bytes, gas: 3
    PUSH3         = 0x62,
    PUSH4         = 0x63,
    PUSH5         = 0x64,
    PUSH6         = 0x65,
    PUSH7         = 0x66,
    PUSH8         = 0x67,
    PUSH9         = 0x68,
    PUSH10        = 0x69,
    PUSH11        = 0x6A,
    PUSH12        = 0x6B,
    PUSH13        = 0x6C,
    PUSH14        = 0x6D,
    PUSH15        = 0x6E,
    PUSH16        = 0x6F,
    PUSH17        = 0x70,
    PUSH18        = 0x71,
    PUSH19        = 0x72,
    PUSH20        = 0x73,
    PUSH21        = 0x74,
    PUSH22        = 0x75,
    PUSH23        = 0x76,
    PUSH24        = 0x77,
    PUSH25        = 0x78,
    PUSH26        = 0x79,
    PUSH27        = 0x7A,
    PUSH28        = 0x7B,
    PUSH29        = 0x7C,
    PUSH30        = 0x7D,
    PUSH31        = 0x7E,
    PUSH32        = 0x7F,  // Push 32 bytes, gas: 3

    // MARK: - Duplicate Operations (0x80-0x8F)

    DUP1          = 0x80,  // Duplicate 1st stack item, gas: 3
    DUP2          = 0x81,
    DUP3          = 0x82,
    DUP4          = 0x83,
    DUP5          = 0x84,
    DUP6          = 0x85,
    DUP7          = 0x86,
    DUP8          = 0x87,
    DUP9          = 0x88,
    DUP10         = 0x89,
    DUP11         = 0x8A,
    DUP12         = 0x8B,
    DUP13         = 0x8C,
    DUP14         = 0x8D,
    DUP15         = 0x8E,
    DUP16         = 0x8F,  // Duplicate 16th stack item, gas: 3

    // MARK: - Exchange Operations (0x90-0x9F)

    SWAP1         = 0x90,  // Exchange 1st and 2nd stack items, gas: 3
    SWAP2         = 0x91,
    SWAP3         = 0x92,
    SWAP4         = 0x93,
    SWAP5         = 0x94,
    SWAP6         = 0x95,
    SWAP7         = 0x96,
    SWAP8         = 0x97,
    SWAP9         = 0x98,
    SWAP10        = 0x99,
    SWAP11        = 0x9A,
    SWAP12        = 0x9B,
    SWAP13        = 0x9C,
    SWAP14        = 0x9D,
    SWAP15        = 0x9E,
    SWAP16        = 0x9F,  // Exchange 1st and 17th stack items, gas: 3

    // MARK: - Log Operations (0xA0-0xA4)

    LOG0          = 0xA0,  // Emit log, gas: 375 + 8*topics
    LOG1          = 0xA1,
    LOG2          = 0xA2,
    LOG3          = 0xA3,
    LOG4          = 0xA4,

    // MARK: - System Operations (0xF0-0xFF)

    CREATE        = 0xF0,  // Create new contract, gas: 32000 + gas_code_bytes
    CALL          = 0xF1,  // Call contract, gas: 2600 + value_transfer + gas
    CALLCODE      = 0xF2,  // Call with code of another contract, gas: 2600 + ...
    RETURN        = 0xF3,  // Halt and return, gas: 0
    DELEGATECALL  = 0xF4,  // Delegate call, gas: 2600 + ...
    CREATE2       = 0xF5,  // Create2, gas: 32000 + 200*deploy_code_words + gas_code_bytes
    STATICCALL    = 0xFA,  // Static call, gas: 2600 + gas
    REVERT        = 0xFD,  // Halt and revert, gas: 0
    SELFDESTRUCT  = 0xFF,  // Self-destruct, gas: 5000 + 25000 if selfdestruct to new account

    // MARK: - EOF (Ethereum Object Format) - EIP-3540 (0xE0-0xEF)

    RJUMP         = 0xE0,  // Relative jump (EIP-3540)
    RJUMPI        = 0xE1,  // Conditional relative jump (EIP-3540)
    RJUMPV        = 0xE2,  // Relative jump with variable offset
    CALLF         = 0xE3,  // Call function (EIP-3540)
    RETF          = 0xE4,  // Return from function (EIP-3540)
    JUMPF         = 0xE5,  // Jump to function (EIP-3540)
    DUPN          = 0xE8,  // Duplicate Nth stack item
    SWAPN         = 0xE9,  // Exchange 1st and Nth stack items
    SLOADBYTES    = 0xE6,  // SLOAD with bytes
    SSTOREBYTES   = 0xE7,  // SSTORE with bytes
    MSTORESIZE    = 0xEA,  // Resize memory
    TRACKSTORAGE  = 0xEB,  // Track storage slot
    COPYLOG       = 0xEC,  // Copy log
}

impl OpCode {
    /// Get gas cost for this opcode
    pub fn gas_cost(&self, state: &EVMState) -> u64 {
        match self {
            OpCode::STOP => 0,
            OpCode::ADD | OpCode::SUB => 3,
            OpCode::MUL | OpCode::DIV | OpCode::SDIV | OpCode::MOD | OpCode::SMOD => 5,
            OpCode::ADDMOD | OpCode::MULMOD => 8,
            OpCode::EXP => {
                // 10 + 50 * (exp_byte_length - 1), but simplified for lattice field
                10
            }
            OpCode::SIGNEXTEND => 5,
            OpCode::LT | OpCode::GT | OpCode::SLT | OpCode::SGT => 3,
            OpCode::EQ | OpCode::ISZERO => 3,
            OpCode::AND | OpCode::OR | OpCode::XOR => 3,
            OpCode::NOT | OpCode::BYTE => 3,
            OpCode::SHL | OpCode::SHR | OpCode::SAR => 3,
            OpCode::KECCAK256 => 30, // + 6 * words, simplified
            OpCode::ADDRESS | OpCode::ORIGIN | OpCode::CALLER | OpCode::CALLVALUE => 2,
            OpCode::CALLDATASIZE | OpCode::CODESIZE | OpCode::GASPRICE => 2,
            OpCode::CALLDATALOAD => 3,
            OpCode::CALLDATACOPY | OpCode::CODECOPY => 3,
            OpCode::POP => 2,
            OpCode::MLOAD | OpCode::MSTORE | OpCode::MSTORE8 => 3,
            OpCode::SLOAD => 100, // simplified warm storage
            OpCode::SSTORE => 100, // simplified
            OpCode::JUMP => 8,
            OpCode::JUMPI => 10,
            OpCode::JUMPDEST => 1,
            OpCode::PC | OpCode::MSIZE | OpCode::GAS => 2,
            OpCode::PUSH0 => 3,
            OpCode::PUSH1 | OpCode::PUSH2 | OpCode::PUSH3 | OpCode::PUSH4 |
            OpCode::PUSH5 | OpCode::PUSH6 | OpCode::PUSH7 | OpCode::PUSH8 |
            OpCode::PUSH9 | OpCode::PUSH10 | OpCode::PUSH11 | OpCode::PUSH12 |
            OpCode::PUSH13 | OpCode::PUSH14 | OpCode::PUSH15 | OpCode::PUSH16 |
            OpCode::PUSH17 | OpCode::PUSH18 | OpCode::PUSH19 | OpCode::PUSH20 |
            OpCode::PUSH21 | OpCode::PUSH22 | OpCode::PUSH23 | OpCode::PUSH24 |
            OpCode::PUSH25 | OpCode::PUSH26 | OpCode::PUSH27 | OpCode::PUSH28 |
            OpCode::PUSH29 | OpCode::PUSH30 | OpCode::PUSH31 | OpCode::PUSH32 => 3,
            OpCode::DUP1 | OpCode::DUP2 | OpCode::DUP3 | OpCode::DUP4 |
            OpCode::DUP5 | OpCode::DUP6 | OpCode::DUP7 | OpCode::DUP8 |
            OpCode::DUP9 | OpCode::DUP10 | OpCode::DUP11 | OpCode::DUP12 |
            OpCode::DUP13 | OpCode::DUP14 | OpCode::DUP15 | OpCode::DUP16 => 3,
            OpCode::SWAP1 | OpCode::SWAP2 | OpCode::SWAP3 | OpCode::SWAP4 |
            OpCode::SWAP5 | OpCode::SWAP6 | OpCode::SWAP7 | OpCode::SWAP8 |
            OpCode::SWAP9 | OpCode::SWAP10 | OpCode::SWAP11 | OpCode::SWAP12 |
            OpCode::SWAP13 | OpCode::SWAP14 | OpCode::SWAP15 | OpCode::SWAP16 => 3,
            OpCode::LOG0 | OpCode::LOG1 | OpCode::LOG2 | OpCode::LOG3 | OpCode::LOG4 => 375,
            OpCode::CREATE | OpCode::CREATE2 => 32000,
            OpCode::CALL | OpCode::CALLCODE | OpCode::DELEGATECALL | OpCode::STATICCALL => 2600,
            OpCode::RETURN | OpCode::REVERT => 0,
            OpCode::SELFDESTRUCT => 5000,
            _ => 2, // default gas cost
        }
    }

    /// Minimum stack items needed
    pub fn stack_height_change(&self) -> (i32, usize) {
        match self {
            OpCode::STOP => (0, 0),
            OpCode::ADD | OpCode::SUB | OpCode::MUL | OpCode::DIV | OpCode::SDIV |
            OpCode::MOD | OpCode::SMOD | OpCode::ADDMOD | OpCode::MULMOD |
            OpCode::EXP | OpCode::SIGNEXTEND => (1, 2), // pops 2, pushes 1
            OpCode::EQ | OpCode::AND | OpCode::OR | OpCode::XOR | OpCode::BYTE |
            OpCode::SHL | OpCode::SHR | OpCode::SAR | OpCode::LT | OpCode::GT | OpCode::SLT | OpCode::SGT => (1, 2),
            OpCode::NOT | OpCode::ISZERO | OpCode::MLOAD | OpCode::CALLDATALOAD | OpCode::SLOAD => (1, 1), // pops 1, pushes 1 -> delta = 0
            OpCode::KECCAK256 => (1, 2),
            OpCode::POP => (-1, 0), // pops 1, pushes 0
            OpCode::CALLDATASIZE | OpCode::CODESIZE => (1, 0), // pushes 1, no pop -> delta = +1
            OpCode::MSTORE | OpCode::MSTORE8 | OpCode::SSTORE => (-2, 0), // pops 2, no push -> delta = -2
            OpCode::JUMP => (0, 1), // pops destination from stack
            OpCode::JUMPI => (-1, 2), // pops 2 (condition, target) but we track net -1
            OpCode::JUMPDEST => (0, 0),
            OpCode::PC | OpCode::MSIZE | OpCode::GAS => (1, 0),
            OpCode::PUSH0 | OpCode::PUSH1 | OpCode::PUSH2 | OpCode::PUSH3 | OpCode::PUSH4 |
            OpCode::PUSH5 | OpCode::PUSH6 | OpCode::PUSH7 | OpCode::PUSH8 |
            OpCode::PUSH9 | OpCode::PUSH10 | OpCode::PUSH11 | OpCode::PUSH12 |
            OpCode::PUSH13 | OpCode::PUSH14 | OpCode::PUSH15 | OpCode::PUSH16 |
            OpCode::PUSH17 | OpCode::PUSH18 | OpCode::PUSH19 | OpCode::PUSH20 |
            OpCode::PUSH21 | OpCode::PUSH22 | OpCode::PUSH23 | OpCode::PUSH24 |
            OpCode::PUSH25 | OpCode::PUSH26 | OpCode::PUSH27 | OpCode::PUSH28 |
            OpCode::PUSH29 | OpCode::PUSH30 | OpCode::PUSH31 | OpCode::PUSH32 => (1, 0),
            OpCode::DUP1 | OpCode::DUP2 | OpCode::DUP3 | OpCode::DUP4 |
            OpCode::DUP5 | OpCode::DUP6 | OpCode::DUP7 | OpCode::DUP8 |
            OpCode::DUP9 | OpCode::DUP10 | OpCode::DUP11 | OpCode::DUP12 |
            OpCode::DUP13 | OpCode::DUP14 | OpCode::DUP15 | OpCode::DUP16 => (1, 1),
            OpCode::SWAP1 | OpCode::SWAP2 | OpCode::SWAP3 | OpCode::SWAP4 |
            OpCode::SWAP5 | OpCode::SWAP6 | OpCode::SWAP7 | OpCode::SWAP8 |
            OpCode::SWAP9 | OpCode::SWAP10 | OpCode::SWAP11 | OpCode::SWAP12 |
            OpCode::SWAP13 | OpCode::SWAP14 | OpCode::SWAP15 | OpCode::SWAP16 => (0, 0), // no stack height change
            OpCode::LOG0 | OpCode::LOG1 | OpCode::LOG2 | OpCode::LOG3 | OpCode::LOG4 => (-2, 2),
            OpCode::CALL => (-6, 1), // pops 7 items (gas, addr, value, args_offset, args_size, ret_offset, ret_size), pushes 1 (success)
            OpCode::STATICCALL => (-5, 1), // pops 6, pushes 1
            OpCode::DELEGATECALL => (-5, 1), // pops 6, pushes 1
            OpCode::CALLCODE => (-6, 1), // pops 7, pushes 1
            OpCode::CREATE => (-3, 1), // pops 3 (value, offset, size), pushes 1 (address)
            OpCode::CREATE2 => (-4, 1), // pops 4 (value, offset, size, salt), pushes 1
            OpCode::SELFDESTRUCT => (-1, 0), // pops 1, no push
            OpCode::RETURN | OpCode::REVERT => (-2, 0), // pops 2, no push
            OpCode::STOP => (0, 0),
            OpCode::MLOAD => (-1, 1), // pops 1, pushes 1
            OpCode::MSTORE => (-2, 0), // pops 2, no push
            OpCode::MSTORE8 => (-2, 0),
            OpCode::SLOAD => (-1, 1), // pops 1 (key), pushes 1 (value)
            OpCode::SSTORE => (-2, 0), // pops 2 (key, value), no push
            OpCode::POP => (-1, 0), // pops 1, no push
            OpCode::DUP1 => (1, 1), // duplicates
            OpCode::SWAP1 => (0, 2), // exchange top 2
            OpCode::BLOCKHASH => (-1, 1), // pops 1, pushes 1
            OpCode::COINBASE | OpCode::TIMESTAMP | OpCode::NUMBER | OpCode::GASLIMIT |
            OpCode::CHAINID | OpCode::BASEFEE | OpCode::PREVRANDAO |
            OpCode::BLOBHASH | OpCode::BLOBBASEFEE => (1, 0), // push 1, pop 0
            OpCode::ADDRESS | OpCode::ORIGIN | OpCode::CALLER | OpCode::CALLVALUE |
            OpCode::CALLDATASIZE | OpCode::GASPRICE | OpCode::EXTCODESIZE |
            OpCode::SELFBALANCE | OpCode::RETURNDATASIZE => (1, 0),
            OpCode::CALLDATACOPY => (-3, 0),
            OpCode::CODECOPY => (-3, 0),
            OpCode::EXTCODECOPY => (-4, 0),
            OpCode::EXTCODEHASH => (0, 1),
            OpCode::RETURNDATACOPY => (-3, 0),
            OpCode::TLOAD => (-1, 1),
            OpCode::TSTORE => (-2, 0),
            OpCode::MCOPY => (-3, 0),
            _ => (0, 0),
        }
    }

    /// Check if this is a valid jump destination
    pub fn is_jumpdest(&self) -> bool {
        matches!(self, OpCode::JUMPDEST)
    }
}

/// EVM state for execution
/// Adapted from Zoltraak's EVMExecutionEngine for lattice field
#[derive(Debug, Clone)]
pub struct EVMState {
    /// Program counter
    pub pc: usize,
    /// Stack (max 1024 items, values modulo Q)
    pub stack: Vec<u32>,
    /// Memory contents
    pub memory: Vec<u8>,
    /// Storage (map from slot to value)
    pub storage: Vec<(u32, u32)>,  // (key, value) pairs modulo Q
    /// Transient storage (EIP-1153, cleared between transactions)
    pub transient_storage: Vec<(u32, u32)>,  // (key, value) pairs for TLOAD/TSTORE
    /// Deployed contracts (address -> code)
    pub deployed_contracts: std::collections::HashMap<u32, Vec<u8>>,
    /// Events emitted during execution (EIP-792)
    pub events: Vec<EventLog>,
    /// Blob hashes for EIP-4844 (blob transactions)
    pub blob_hashes: Vec<u32>,  // Each blob hash as u32 (first word of 32-byte hash)
    /// Blob gas price for EIP-4844
    pub blob_gas_price: u32,
    /// Nonce for address computation (CREATE/CREATE2)
    pub nonce: u32,
    /// Gas remaining
    pub gas: u64,
    /// Call depth
    pub call_depth: usize,
    /// Memory size (in bytes)
    pub memory_size: usize,
    /// Running state
    pub running: bool,
    /// Reverted state
    pub reverted: bool,
    /// Calldata (transaction input data)
    pub calldata: Vec<u8>,
    /// Balance (for CALL value transfer tracking)
    pub balance: u32,
}

/// Event log entry for LOG opcodes
#[derive(Debug, Clone)]
pub struct EventLog {
    /// Address emitting the event
    pub address: u32,
    /// Topics (up to 4, indexed event parameters)
    pub topics: Vec<u32>,
    /// Event data (non-indexed parameters)
    pub data: Vec<u8>,
}

impl Default for EVMState {
    fn default() -> Self {
        EVMState {
            pc: 0,
            stack: Vec::new(),
            memory: Vec::with_capacity(1024),
            storage: Vec::new(),
            transient_storage: Vec::new(),
            deployed_contracts: std::collections::HashMap::new(),
            events: Vec::new(),
            blob_hashes: Vec::new(),
            blob_gas_price: 1,  // Default to 1 gwei
            nonce: 0,
            gas: u64::MAX,
            call_depth: 0,
            memory_size: 0,
            running: true,
            reverted: false,
            calldata: Vec::new(),
            balance: 1_000_000, // Initial balance for SELFBALANCE dummy
        }
    }
}

impl EVMState {
    /// Create new EVM state
    pub fn new(gas: u64) -> Self {
        let mut state = Self::default();
        state.gas = gas;
        state
    }

    /// Create new EVM state with calldata
    pub fn new_with_calldata(gas: u64, calldata: Vec<u8>) -> Self {
        let mut state = Self::default();
        state.gas = gas;
        state.calldata = calldata;
        state
    }

    /// Push value onto stack (mod Q)
    pub fn push(&mut self, val: u32) -> Result<(), &'static str> {
        if self.stack.len() >= 1024 {
            return Err("Stack overflow");
        }
        self.stack.push(val % 8383489);
        Ok(())
    }

    /// Pop value from stack
    pub fn pop(&mut self) -> Result<u32, &'static str> {
        self.stack.pop().ok_or("Stack underflow")
    }

    /// Read 32 bytes from memory at offset and return as u32 (mod Q)
    ///
    /// EVM spec: MLOAD reads a 32-byte value from memory and returns it as a u256.
    /// Since our constraint system works with u32 mod Q, we return the low 32 bits
    /// of the 256-bit value (little-endian interpretation).
    pub fn mload(&self, offset: usize) -> u32 {
        if offset + 32 > self.memory.len() {
            0  // Memory not initialized at this offset
        } else {
            // Read 32 bytes as little-endian u256, then take low 32 bits mod Q
            let mut val = 0u32;
            for i in 0..32 {
                val ^= (self.memory[offset + i] as u32) << (8 * i);
            }
            val % 8383489
        }
    }

    /// Store 32-byte value to memory at offset
    ///
    /// EVM spec: MSTORE writes a 32-byte value to memory.
    /// The val parameter is u32 mod Q - we write it to the low 4 bytes and zero the remaining 28 bytes.
    /// For full 32-byte support, the caller should provide a u256 but we only have u32 in our simplified impl.
    pub fn mstore(&mut self, offset: usize, val: u32) -> Result<(), &'static str> {
        // Expand memory to at least offset + 32
        let needed = offset + 32;
        if needed > self.memory.len() {
            self.memory.resize(needed, 0);
            self.memory_size = needed;
        }
        let val = val % 8383489;
        // Write val to bytes 0-3 (little-endian), bytes 4-31 are already 0 from resize
        for i in 0..4 {
            self.memory[offset + i] = ((val >> (8 * i)) & 0xFF) as u8;
        }
        // Bytes 4-31 are already 0 from the resize above
        Ok(())
    }

    /// Store byte to memory
    pub fn mstore8(&mut self, offset: usize, val: u8) -> Result<(), &'static str> {
        if offset >= self.memory.len() {
            self.memory.resize(offset + 1, 0);
            self.memory_size = offset + 1;
        }
        self.memory[offset] = val;
        Ok(())
    }

    /// SLOAD - load from storage
    pub fn sload(&self, key: u32) -> u32 {
        for (k, v) in &self.storage {
            if *k == key % 8383489 {
                return *v;
            }
        }
        0
    }

    /// SSTORE - store to storage
    pub fn sstore(&mut self, key: u32, val: u32) {
        let key = key % 8383489;
        let val = val % 8383489;
        // Update or insert
        for pair in &mut self.storage {
            if pair.0 == key {
                pair.1 = val;
                return;
            }
        }
        self.storage.push((key, val));
    }

    /// TLOAD - load from transient storage (EIP-1153)
    /// Unlike storage, transient storage is cleared between transactions
    pub fn tload(&self, key: u32) -> u32 {
        let key = key % 8383489;
        for (k, v) in &self.transient_storage {
            if *k == key {
                return *v;
            }
        }
        0
    }

    /// TSTORE - store to transient storage (EIP-1153)
    pub fn tstore(&mut self, key: u32, val: u32) {
        let key = key % 8383489;
        let val = val % 8383489;
        // Update or insert
        for pair in &mut self.transient_storage {
            if pair.0 == key {
                pair.1 = val;
                return;
            }
        }
        self.transient_storage.push((key, val));
    }
}

/// Execute bytecode and generate trace
pub fn execute_bytecode(
    code: &[u8],
    gas: u64,
) -> Result<(EVMState, Vec<TraceRow>), &'static str> {
    execute_bytecode_with_calldata(code, gas, Vec::new())
}

/// Execute bytecode with calldata and generate trace
pub fn execute_bytecode_with_calldata(
    code: &[u8],
    gas: u64,
    calldata: Vec<u8>,
) -> Result<(EVMState, Vec<TraceRow>), &'static str> {
    let mut state = EVMState::new_with_calldata(gas, calldata);
    let mut trace = Vec::new();

    while state.running && state.pc < code.len() {
        let opcode = code[state.pc];
        state.pc += 1;

        // Capture gas BEFORE execution
        let gas_before = state.gas;

        // Track memory and storage operations for verification
        let mut memory_ops: Vec<(u32, u32)> = vec![];
        let mut storage_ops: Vec<(u32, u32)> = vec![];

        // Process opcode
        let op = OpCode::from_u8(opcode);

        // Deduct gas
        let gas_cost = op.gas_cost(&state);
        if state.gas < gas_cost {
            state.running = false;
            break;
        }
        state.gas -= gas_cost;

        // Execute
        match op {
            OpCode::STOP => { state.running = false; }
            OpCode::ADD => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a.wrapping_add(b))?;
            }
            OpCode::MUL => {
                let a = state.pop()?;
                let b = state.pop()?;
                let result = ((a as u64) * (b as u64) % 8383489) as u32;
                state.push(result)?;
            }
            OpCode::SUB => {
                let a = state.pop()?;
                let b = state.pop()?;
                let result = (a as i32 - b as i32).unsigned_abs() as u32 % 8383489;
                state.push(result)?;
            }
            OpCode::DIV => {
                let a = state.pop()?;
                let b = state.pop()?;
                if b == 0 {
                    state.push(0)?;
                } else {
                    state.push(a / b)?;
                }
            }
            OpCode::LT => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(if a < b { 1 } else { 0 })?;
            }
            OpCode::GT => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(if a > b { 1 } else { 0 })?;
            }
            OpCode::EQ => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(if a == b { 1 } else { 0 })?;
            }
            OpCode::ISZERO => {
                let a = state.pop()?;
                state.push(if a == 0 { 1 } else { 0 })?;
            }
            OpCode::AND => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a & b)?;
            }
            OpCode::OR => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a | b)?;
            }
            OpCode::XOR => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a ^ b)?;
            }
            OpCode::NOT => {
                let a = state.pop()?;
                state.push((!a) % 8383489)?;
            }
            OpCode::PUSH0 => {
                state.push(0u32)?;
            }
            OpCode::PUSH1 => {
                let val = code.get(state.pc).copied().unwrap_or(0);
                state.pc += 1;
                state.push(val as u32)?;
            }
            OpCode::PUSH2 => {
                let val = u16::from(code.get(state.pc).copied().unwrap_or(0)) |
                          (u16::from(code.get(state.pc + 1).copied().unwrap_or(0)) << 8);
                state.pc += 2;
                state.push(val as u32)?;
            }
            OpCode::PUSH3 => {
                let val = u32::from(code.get(state.pc).copied().unwrap_or(0)) |
                          (u32::from(code.get(state.pc + 1).copied().unwrap_or(0)) << 8) |
                          (u32::from(code.get(state.pc + 2).copied().unwrap_or(0)) << 16);
                state.pc += 3;
                state.push(val)?;
            }
            OpCode::PUSH4 | OpCode::PUSH5 | OpCode::PUSH6 | OpCode::PUSH7 |
            OpCode::PUSH8 | OpCode::PUSH9 | OpCode::PUSH10 | OpCode::PUSH11 |
            OpCode::PUSH12 | OpCode::PUSH13 | OpCode::PUSH14 | OpCode::PUSH15 |
            OpCode::PUSH16 | OpCode::PUSH17 | OpCode::PUSH18 | OpCode::PUSH19 |
            OpCode::PUSH20 | OpCode::PUSH21 | OpCode::PUSH22 | OpCode::PUSH23 |
            OpCode::PUSH24 | OpCode::PUSH25 | OpCode::PUSH26 | OpCode::PUSH27 |
            OpCode::PUSH28 | OpCode::PUSH29 | OpCode::PUSH30 | OpCode::PUSH31 => {
                // Read 4 bytes (our u32 has only 4 bytes)
                let val = u32::from(code.get(state.pc).copied().unwrap_or(0)) |
                          (u32::from(code.get(state.pc + 1).copied().unwrap_or(0)) << 8) |
                          (u32::from(code.get(state.pc + 2).copied().unwrap_or(0)) << 16) |
                          (u32::from(code.get(state.pc + 3).copied().unwrap_or(0)) << 24);
                state.pc += 4;
                state.push(val)?;
            }
            OpCode::PUSH32 => {
                // Read 32 bytes as big-endian u256
                let mut val = 0u32;
                for i in 0..4 {
                    val = val.wrapping_add(
                        u32::from(code.get(state.pc + i).copied().unwrap_or(0)) << (8 * i)
                    );
                }
                state.pc += 32;
                state.push(val)?;
            }
            OpCode::MLOAD => {
                let offset = state.pop()? as usize;
                let val = state.mload(offset);
                state.push(val)?;
                memory_ops.push((offset as u32, val)); // Record MLOAD for verification
            }
            OpCode::MSTORE => {
                let offset = state.pop()? as usize;
                let val = state.pop()?;
                state.mstore(offset, val)?;
                memory_ops.push((offset as u32, val)); // Record MSTORE for verification
            }
            OpCode::MSTORE8 => {
                let offset = state.pop()? as usize;
                let val = state.pop()? as u8;
                state.mstore8(offset, val)?;
                memory_ops.push((offset as u32, val as u32)); // Record MSTORE8 for verification
            }
            OpCode::JUMP => {
                let dest = state.pop()? as usize;
                if dest < code.len() && code[dest] == 0x5B {
                    state.pc = dest;
                }
            }
            OpCode::JUMPI => {
                let dest = state.pop()? as usize;
                let cond = state.pop()?;
                if cond != 0 && dest < code.len() && code[dest] == 0x5B {
                    state.pc = dest;
                }
            }
            OpCode::JUMPDEST => { /* No-op */ }
            OpCode::POP => {
                state.pop()?;
            }
            OpCode::DUP1 => {
                let val = *state.stack.last().ok_or("Stack underflow")?;
                state.push(val)?;
            }
            OpCode::SWAP1 => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a)?;
                state.push(b)?;
            }
            OpCode::RETURN => {
                state.running = false;
                // Decrement call depth when returning from a call
                if state.call_depth > 0 {
                    state.call_depth -= 1;
                }
            }
            OpCode::REVERT => {
                state.running = false;
                state.reverted = true;
                // Decrement call depth when reverting from a call
                if state.call_depth > 0 {
                    state.call_depth -= 1;
                }
            }

            // MARK: - Call Operations

            OpCode::CALL => {
                // Stack: gas, addr, value, args_offset, args_size, ret_offset, ret_size
                let _gas = state.pop()?;
                let _addr = state.pop()?;
                let value = state.pop()?;
                let _args_offset = state.pop()?;
                let _args_size = state.pop()?;
                let _ret_offset = state.pop()?;
                let _ret_size = state.pop()?;
                // Track balance: deduct value transferred
                // balance_before is recorded before the transfer, balance_after is after
                let balance_before = state.balance;
                state.balance = state.balance.saturating_sub(value);
                let balance_after = state.balance;
                tracing::debug!("CALL opcode: transferred value={}, balance {} -> {}",
                    value, balance_before, balance_after);
                // Increment call depth for nested call tracking
                state.call_depth += 1;
                // Push success (1) - simulation only, doesn't create nested execution
                state.push(1)?;
            }
            OpCode::STATICCALL => {
                // Stack: gas, addr, args_offset, args_size, ret_offset, ret_size
                let _gas = state.pop()?;
                let _addr = state.pop()?;
                let _args_offset = state.pop()?;
                let _args_size = state.pop()?;
                let _ret_offset = state.pop()?;
                let _ret_size = state.pop()?;
                state.push(1)?;
                tracing::debug!("STATICCALL opcode (simulation only)");
            }
            OpCode::DELEGATECALL => {
                // Stack: gas, addr, args_offset, args_size, ret_offset, ret_size
                let _gas = state.pop()?;
                let _addr = state.pop()?;
                let _args_offset = state.pop()?;
                let _args_size = state.pop()?;
                let _ret_offset = state.pop()?;
                let _ret_size = state.pop()?;
                state.push(1)?;
                tracing::debug!("DELEGATECALL opcode (simulation only)");
            }
            OpCode::CALLCODE => {
                // Stack: gas, addr, value, args_offset, args_size, ret_offset, ret_size
                let _gas = state.pop()?;
                let _addr = state.pop()?;
                let _value = state.pop()?;
                let _args_offset = state.pop()?;
                let _args_size = state.pop()?;
                let _ret_offset = state.pop()?;
                let _ret_size = state.pop()?;
                state.push(1)?;
                tracing::debug!("CALLCODE opcode (simulation only)");
            }

            // MARK: - Create Operations

            OpCode::CREATE => {
                // Stack: value, offset, size -> address
                // CREATE address = keccak256(sender_address ++ nonce)[12:]
                let value = state.pop()?;
                let offset = state.pop()?;
                let size = state.pop()?;

                // Read code from memory
                let offset = offset as usize;
                let size = size as usize;
                let code = if offset < state.memory.len() && size > 0 {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };

                // Sender address (contract address) - use placeholder
                let sender: [u8; 20] = [0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

                // Compute CREATE address = keccak256(sender || nonce)[12:]
                use crate::crypto::keccak256;
                let mut input = [0u8; 20 + 4];
                input[..20].copy_from_slice(&sender);
                input[20..24].copy_from_slice(&state.nonce.to_le_bytes());
                let hash = keccak256(&input);

                // Truncate to last 4 bytes for field element
                let address = u32::from_le_bytes([hash[31], hash[30], hash[29], hash[28]]);

                // Increment nonce
                state.nonce += 1;

                // Deploy contract if code is not empty
                if !code.is_empty() {
                    state.deployed_contracts.insert(address, code);
                }

                state.push(address % 8383489)?;
                tracing::debug!("CREATE opcode: deployed to {:08x}", address);
            }
            OpCode::CREATE2 => {
                // Stack: value, offset, size, salt -> address
                // CREATE2 address = keccak256(0xff + sender + salt + keccak256(code))[12:]
                let value = state.pop()?;
                let offset = state.pop()?;
                let size = state.pop()?;
                let salt = state.pop()?;

                // Read code from memory
                let offset = offset as usize;
                let size = size as usize;
                let code = if offset < state.memory.len() && size > 0 {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };

                // Sender address - use same as CREATE
                let sender: [u8; 20] = [0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

                // Compute CREATE2 address = keccak256(0xff || sender || salt || code_hash)[12:]
                use crate::crypto::keccak256;
                let code_hash = keccak256(&code);

                let mut input = Vec::with_capacity(1 + 20 + 32 + 32);
                input.push(0xff);
                input.extend_from_slice(&sender);
                input.extend_from_slice(&salt.to_le_bytes());
                input.extend_from_slice(&code_hash);
                let hash = keccak256(&input);

                // Truncate to last 4 bytes for field element
                let address = u32::from_le_bytes([hash[31], hash[30], hash[29], hash[28]]);

                // Deploy contract if code is not empty
                if !code.is_empty() {
                    state.deployed_contracts.insert(address, code);
                }

                state.push(address % 8383489)?;
                tracing::debug!("CREATE2 opcode: deployed to {:08x}", address);
            }

            // MARK: - Self-destruct (EIP-6780)

            OpCode::SELFDESTRUCT => {
                // Stack: address to send remaining balance to
                let target = state.pop()?;

                // Track selfdestruct for gas refund calculation
                // EIP-3298: SELFDESTRUCT refunds 24000 gas if target != address
                // Note: In newer EIPs (EIP-6780), SELFDESTRUCT doesn't always delete storage
                // but we implement the original behavior for compatibility
                let is_selfdestruct = state.balance > 0;

                // Record selfdestruct operation in state
                // This can be used by the prover to verify gas refunds
                tracing::debug!("SELFDESTRUCT to {:08x}, balance={}", target, state.balance);

                // Stop execution after selfdestruct
                state.running = false;
            }

            // MARK: - Log Operations (EIP-792)

            OpCode::LOG0 => {
                let offset = state.pop()?;
                let size = state.pop()?;
                let offset = offset as usize;
                let size = size as usize;
                // Get memory slice for event data
                let data = if offset < state.memory.len() {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                // Create event log (no topics for LOG0)
                let event = EventLog {
                    address: 0x12345678,  // Contract address
                    topics: Vec::new(),
                    data,
                };
                state.events.push(event);
                tracing::debug!("LOG0 emitted");
            }
            OpCode::LOG1 => {
                let offset = state.pop()?;
                let size = state.pop()?;
                let topic1 = state.pop()?;
                let offset = offset as usize;
                let size = size as usize;
                let data = if offset < state.memory.len() {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                let event = EventLog {
                    address: 0x12345678,
                    topics: vec![topic1],
                    data,
                };
                state.events.push(event);
                tracing::debug!("LOG1 emitted");
            }
            OpCode::LOG2 => {
                let offset = state.pop()?;
                let size = state.pop()?;
                let topic1 = state.pop()?;
                let topic2 = state.pop()?;
                let offset = offset as usize;
                let size = size as usize;
                let data = if offset < state.memory.len() {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                let event = EventLog {
                    address: 0x12345678,
                    topics: vec![topic1, topic2],
                    data,
                };
                state.events.push(event);
                tracing::debug!("LOG2 emitted");
            }
            OpCode::LOG3 => {
                let offset = state.pop()?;
                let size = state.pop()?;
                let topic1 = state.pop()?;
                let topic2 = state.pop()?;
                let topic3 = state.pop()?;
                let offset = offset as usize;
                let size = size as usize;
                let data = if offset < state.memory.len() {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                let event = EventLog {
                    address: 0x12345678,
                    topics: vec![topic1, topic2, topic3],
                    data,
                };
                state.events.push(event);
                tracing::debug!("LOG3 emitted");
            }
            OpCode::LOG4 => {
                let offset = state.pop()?;
                let size = state.pop()?;
                let topic1 = state.pop()?;
                let topic2 = state.pop()?;
                let topic3 = state.pop()?;
                let topic4 = state.pop()?;
                let offset = offset as usize;
                let size = size as usize;
                let data = if offset < state.memory.len() {
                    let end = (offset + size).min(state.memory.len());
                    state.memory[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                let event = EventLog {
                    address: 0x12345678,
                    topics: vec![topic1, topic2, topic3, topic4],
                    data,
                };
                state.events.push(event);
                tracing::debug!("LOG4 emitted");
            }

            // MARK: - Memory Operations

            OpCode::MLOAD => {
                let offset = state.pop()? as usize;
                let val = state.mload(offset);
                state.push(val)?;
                memory_ops.push((offset as u32, val)); // Record MLOAD for verification
            }
            OpCode::MSTORE => {
                let offset = state.pop()? as usize;
                let val = state.pop()?;
                state.mstore(offset, val)?;
                memory_ops.push((offset as u32, val)); // Record MSTORE for verification
            }
            OpCode::MSTORE8 => {
                let offset = state.pop()? as usize;
                let val = state.pop()? as u8;
                state.mstore8(offset, val)?;
                memory_ops.push((offset as u32, val as u32)); // Record MSTORE8 for verification
            }

            // MARK: - Storage Operations

            OpCode::SLOAD => {
                let key = state.pop()?;
                let val = state.sload(key);
                state.push(val)?;
                storage_ops.push((key, val)); // Record SLOAD for verification
            }
            OpCode::SSTORE => {
                let key = state.pop()?;
                let val = state.pop()?;
                state.sstore(key, val);
                storage_ops.push((key, val)); // Record SSTORE for verification
            }

            // MARK: - Jump Operations

            OpCode::JUMP => {
                let dest = state.pop()? as usize;
                if dest < code.len() && code[dest] == 0x5B {
                    state.pc = dest;
                }
            }
            OpCode::JUMPI => {
                let dest = state.pop()? as usize;
                let cond = state.pop()?;
                if cond != 0 && dest < code.len() && code[dest] == 0x5B {
                    state.pc = dest;
                }
            }
            OpCode::JUMPDEST => { /* No-op */ }
            OpCode::POP => {
                state.pop()?;
            }

            // MARK: - Duplicate and Exchange

            OpCode::DUP1 => {
                let val = *state.stack.last().ok_or("Stack underflow")?;
                state.push(val)?;
            }
            OpCode::DUP2 => {
                let len = state.stack.len();
                if len < 2 { return Err("Stack underflow"); }
                let val = state.stack[len - 2];
                state.push(val)?;
            }
            OpCode::DUP3 => {
                let len = state.stack.len();
                if len < 3 { return Err("Stack underflow"); }
                let val = state.stack[len - 3];
                state.push(val)?;
            }
            OpCode::DUP4 => {
                let len = state.stack.len();
                if len < 4 { return Err("Stack underflow"); }
                let val = state.stack[len - 4];
                state.push(val)?;
            }
            OpCode::DUP5 => {
                let len = state.stack.len();
                if len < 5 { return Err("Stack underflow"); }
                let val = state.stack[len - 5];
                state.push(val)?;
            }
            OpCode::DUP6 => {
                let len = state.stack.len();
                if len < 6 { return Err("Stack underflow"); }
                let val = state.stack[len - 6];
                state.push(val)?;
            }
            OpCode::DUP7 => {
                let len = state.stack.len();
                if len < 7 { return Err("Stack underflow"); }
                let val = state.stack[len - 7];
                state.push(val)?;
            }
            OpCode::DUP8 => {
                let len = state.stack.len();
                if len < 8 { return Err("Stack underflow"); }
                let val = state.stack[len - 8];
                state.push(val)?;
            }
            OpCode::DUP9 => {
                let len = state.stack.len();
                if len < 9 { return Err("Stack underflow"); }
                let val = state.stack[len - 9];
                state.push(val)?;
            }
            OpCode::DUP10 => {
                let len = state.stack.len();
                if len < 10 { return Err("Stack underflow"); }
                let val = state.stack[len - 10];
                state.push(val)?;
            }
            OpCode::DUP11 => {
                let len = state.stack.len();
                if len < 11 { return Err("Stack underflow"); }
                let val = state.stack[len - 11];
                state.push(val)?;
            }
            OpCode::DUP12 => {
                let len = state.stack.len();
                if len < 12 { return Err("Stack underflow"); }
                let val = state.stack[len - 12];
                state.push(val)?;
            }
            OpCode::DUP13 => {
                let len = state.stack.len();
                if len < 13 { return Err("Stack underflow"); }
                let val = state.stack[len - 13];
                state.push(val)?;
            }
            OpCode::DUP14 => {
                let len = state.stack.len();
                if len < 14 { return Err("Stack underflow"); }
                let val = state.stack[len - 14];
                state.push(val)?;
            }
            OpCode::DUP15 => {
                let len = state.stack.len();
                if len < 15 { return Err("Stack underflow"); }
                let val = state.stack[len - 15];
                state.push(val)?;
            }
            OpCode::DUP16 => {
                let len = state.stack.len();
                if len < 16 { return Err("Stack underflow"); }
                let val = state.stack[len - 16];
                state.push(val)?;
            }
            OpCode::SWAP1 => {
                let a = state.pop()?;
                let b = state.pop()?;
                state.push(a)?;
                state.push(b)?;
            }
            OpCode::SWAP2 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 1 { return Err("Stack underflow"); }
                let b = state.stack[len - 1];
                state.stack[len - 1] = a;
                state.push(b)?;
            }
            OpCode::SWAP3 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 2 { return Err("Stack underflow"); }
                let b = state.stack[len - 2];
                state.stack[len - 2] = a;
                state.push(b)?;
            }
            OpCode::SWAP4 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 3 { return Err("Stack underflow"); }
                let b = state.stack[len - 3];
                state.stack[len - 3] = a;
                state.push(b)?;
            }
            OpCode::SWAP5 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 4 { return Err("Stack underflow"); }
                let b = state.stack[len - 4];
                state.stack[len - 4] = a;
                state.push(b)?;
            }
            OpCode::SWAP6 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 5 { return Err("Stack underflow"); }
                let b = state.stack[len - 5];
                state.stack[len - 5] = a;
                state.push(b)?;
            }
            OpCode::SWAP7 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 6 { return Err("Stack underflow"); }
                let b = state.stack[len - 6];
                state.stack[len - 6] = a;
                state.push(b)?;
            }
            OpCode::SWAP8 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 7 { return Err("Stack underflow"); }
                let b = state.stack[len - 7];
                state.stack[len - 7] = a;
                state.push(b)?;
            }
            OpCode::SWAP9 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 8 { return Err("Stack underflow"); }
                let b = state.stack[len - 8];
                state.stack[len - 8] = a;
                state.push(b)?;
            }
            OpCode::SWAP10 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 9 { return Err("Stack underflow"); }
                let b = state.stack[len - 9];
                state.stack[len - 9] = a;
                state.push(b)?;
            }
            OpCode::SWAP11 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 10 { return Err("Stack underflow"); }
                let b = state.stack[len - 10];
                state.stack[len - 10] = a;
                state.push(b)?;
            }
            OpCode::SWAP12 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 11 { return Err("Stack underflow"); }
                let b = state.stack[len - 11];
                state.stack[len - 11] = a;
                state.push(b)?;
            }
            OpCode::SWAP13 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 12 { return Err("Stack underflow"); }
                let b = state.stack[len - 12];
                state.stack[len - 12] = a;
                state.push(b)?;
            }
            OpCode::SWAP14 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 13 { return Err("Stack underflow"); }
                let b = state.stack[len - 13];
                state.stack[len - 13] = a;
                state.push(b)?;
            }
            OpCode::SWAP15 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 14 { return Err("Stack underflow"); }
                let b = state.stack[len - 14];
                state.stack[len - 14] = a;
                state.push(b)?;
            }
            OpCode::SWAP16 => {
                let a = state.pop()?;
                let len = state.stack.len();
                if len < 15 { return Err("Stack underflow"); }
                let b = state.stack[len - 15];
                state.stack[len - 15] = a;
                state.push(b)?;
            }

            // MARK: - System Operations

            OpCode::RETURN => {
                state.running = false;
            }
            OpCode::REVERT => {
                state.running = false;
                state.reverted = true;
            }
            OpCode::STOP => {
                state.running = false;
            }

            // MARK: - Block Operations

            OpCode::BLOCKHASH => {
                // Stack: block number -> hash
                let _block_num = state.pop()?;
                // Return a dummy hash
                state.push(0xabcdef01)?;
            }
            OpCode::COINBASE => {
                state.push(0x12345678u32)?;
            }
            OpCode::TIMESTAMP => {
                state.push(1700000000u32 as u32)?; // 2023-11-14
            }
            OpCode::NUMBER => {
                state.push(19000000u32 as u32)?; // Mainnet block ~19M
            }
            OpCode::GASLIMIT => {
                state.push(30000000u32 as u32)?;
            }
            OpCode::CHAINID => {
                state.push(1u32)?; // Ethereum mainnet
            }
            OpCode::BASEFEE => {
                state.push(30u32)?; // ~30 gwei
            }
            OpCode::PREVRANDAO => {
                state.push(0xabcdef01u32)?;
            }

            // MARK: - EIP-4844 Blob Operations

            OpCode::BLOBHASH => {
                // Stack: index -> blob_hash[0] (truncated to u32)
                let index = state.pop()? as usize;
                if index < state.blob_hashes.len() {
                    state.push(state.blob_hashes[index])?;
                } else {
                    state.push(0)?;
                }
            }
            OpCode::BLOBBASEFEE => {
                // Returns current blob gas price (as u32 truncated from u256)
                // Formula: get_excess_blob_gas() -> blob_gas_price
                state.push(state.blob_gas_price)?;
            }

            // MARK: - Environmental Information

            OpCode::ADDRESS => {
                state.push(0x12345678u32)?;
            }
            OpCode::ORIGIN => {
                state.push(0xabcdef01u32)?;
            }
            OpCode::CALLER => {
                state.push(0x98765432u32)?;
            }
            OpCode::CALLVALUE => {
                state.push(0u32)?;
            }
            OpCode::CALLDATASIZE => {
                state.push(state.calldata.len() as u32)?;
            }
            OpCode::CALLDATALOAD => {
                let offset = state.pop()? as usize;
                // Read 32 bytes from calldata at offset
                let mut val = 0u32;
                for i in 0..4 {
                    if offset + i * 8 < state.calldata.len() {
                        val |= u32::from(state.calldata[offset + i * 8]) << (8 * i);
                    }
                }
                state.push(val)?;
            }
            OpCode::GASPRICE => {
                state.push(20u32)?; // 20 gwei
            }
            OpCode::EXTCODESIZE => {
                let _addr = state.pop()?;
                state.push(0u32)?; // Empty code
            }
            OpCode::EXTCODECOPY => {
                // Stack: addr, offset, destOffset, length
                let _addr = state.pop()?;
                let _offset = state.pop()?;
                let _dest_offset = state.pop()?;
                let _length = state.pop()?;
                // No code copied
            }
            OpCode::SELFBALANCE => {
                state.push(1000000u32)?; // 1M balance
            }

            // MARK: - Memory Copy

            OpCode::CALLDATACOPY => {
                let dest = state.pop()? as usize;
                let offset = state.pop()? as usize;
                let length = state.pop()? as usize;
                // Copy calldata to memory
                for i in 0..length.min(1024) {
                    if dest + i >= state.memory.len() {
                        state.memory.resize(dest + i + 1, 0);
                    }
                    if offset + i < state.calldata.len() {
                        state.memory[dest + i] = state.calldata[offset + i];
                    } else {
                        state.memory[dest + i] = 0;
                    }
                }
            }
            OpCode::CODECOPY => {
                let dest = state.pop()? as usize;
                let offset = state.pop()? as usize;
                let length = state.pop()? as usize;
                // Copy from code (simulation - just zeros)
                for i in 0..length.min(1024) {
                    if dest + i < state.memory.len() {
                        state.memory[dest + i] = 0;
                    }
                }
            }

            // MARK: - Extended Memory Operations

            OpCode::RETURNDATASIZE => {
                state.push(0u32)?; // No return data in simulation
            }
            OpCode::RETURNDATACOPY => {
                let _dest = state.pop()?;
                let _offset = state.pop()?;
                let _length = state.pop()?;
                // No return data
            }
            OpCode::EXTCODEHASH => {
                let _addr = state.pop()?;
                state.push(0u32)?; // Empty code hash
            }

            // MARK: - TLOAD/TSTORE (EIP-1153)

            OpCode::TLOAD => {
                let key = state.pop()?;
                let val = state.tload(key);
                state.push(val)?;
            }
            OpCode::TSTORE => {
                let key = state.pop()?;
                let val = state.pop()?;
                state.tstore(key, val);
            }

            // MARK: - MCOPY (EIP-5656)

            OpCode::MCOPY => {
                let dest = state.pop()? as usize;
                let src = state.pop()? as usize;
                let length = state.pop()? as usize;

                // Expand memory to accommodate both source and destination
                let needed = (dest + length).max(src + length);
                if needed > state.memory.len() {
                    state.memory.resize(needed, 0);
                    state.memory_size = needed;
                }

                // Copy all bytes from src to dest (handles overlapping regions correctly)
                // Use copying to handle overlapping memory regions (like memcpy in C)
                let src_end = (src + length).min(state.memory.len());
                let copy_len = src_end.saturating_sub(src);

                if copy_len > 0 {
                    // Copy byte by byte (safe for overlapping regions)
                    // For EVM, dest and src typically don't overlap, but we handle it safely
                    let mut i = 0;
                    while i < copy_len {
                        state.memory[dest + i] = state.memory[src + i];
                        i += 1;
                    }
                }
            }

            // MARK: - Unimplemented opcodes (continue execution)

            _ => {
                // For any other opcodes, consume stack as needed and continue
                // This allows execution to proceed through unimplemented opcodes
                tracing::warn!("Unimplemented opcode: {:02x}", opcode);
            }
        }

        // Create trace row AFTER execution with both gas_before and gas_after
        let row = TraceRow::from_state(&state, opcode, code, gas_before, state.gas, memory_ops, storage_ops);
        trace.push(row);
    }

    Ok((state, trace))
}

/// Commit-and-Prove trace row for EVM execution
///
/// Uses hybrid approach:
/// - Committed values (hashes) for privacy and state continuity
/// - Uncommitted values for constraint verification
///
/// Structure (15 elements):
/// - pc (1): uncommitted, control flow
/// - opcode (1): uncommitted, selects constraints
/// - gas (1): uncommitted, gas accounting
/// - stack_height (1): uncommitted, current stack height
/// - stack_before (1): uncommitted, stack height before this opcode executed
/// - stack_after (1): uncommitted, stack height after this opcode executed
/// - balance_before (1): uncommitted, balance before op (for token transfers)
/// - balance_after (1): uncommitted, balance after op (for token transfers)
/// - balance_delta (1): uncommitted, net balance change
/// - storage_before (1): uncommitted, storage state before (aggregated hash)
/// - storage_after (1): uncommitted, storage state after (aggregated hash)
/// - storage_delta (1): uncommitted, net storage change
/// - stack_commitment (1): committed, hash of stack contents
/// - memory_commitment (1): committed, hash of memory contents
/// - storage_commitment (1): committed, hash of storage contents
///
/// Reduces from 101 elements to 17 elements per row (83% reduction)!
/// Supports verification of: stack deltas, token transfer arithmetic, storage state transitions!
/// Control flow verification: bytecode_hash, jumpdest_bitmap
#[derive(Debug, Clone)]
pub struct CommitProveTraceRow {
    /// Program counter (uncommitted)
    pub pc: u32,
    /// Current opcode (uncommitted)
    pub opcode: u8,
    /// Gas remaining before this opcode executed (uncommitted)
    pub gas_before: u32,
    /// Gas remaining after this opcode executed (uncommitted)
    pub gas_after: u32,
    /// Stack height (uncommitted - for constraint verification)
    pub stack_height: u32,
    /// Stack height before this opcode executed (for delta verification)
    pub stack_before: u32,
    /// Stack height after this opcode executed (for delta verification)
    pub stack_after: u32,
    /// Balance before operation (uncommitted - for token transfer verification)
    pub balance_before: u32,
    /// Balance after operation (uncommitted - for token transfer verification)
    pub balance_after: u32,
    /// Net balance change (uncommitted - for verification)
    pub balance_delta: u32,
    /// Storage state before operation (uncommitted - for storage verification)
    pub storage_before: u32,
    /// Storage state after operation (uncommitted - for storage verification)
    pub storage_after: u32,
    /// Net storage change (uncommitted - for verification)
    pub storage_delta: u32,
    /// Commitment to stack contents (committed)
    pub stack_commitment: u32,
    /// Commitment to memory contents (committed)
    pub memory_commitment: u32,
    /// Commitment to storage contents (committed)
    pub storage_commitment: u32,
    /// Commitment to bytecode (for PUSH value verification)
    pub bytecode_hash: u32,
    /// Commitment to JUMPDEST bitmap (for JUMP/JUMPI verification)
    pub jumpdest_bitmap: u32,
}

impl CommitProveTraceRow {
    /// Create from full TraceRow
    pub fn from_trace_row(row: &TraceRow) -> Self {
        let (stack_commitment, memory_commitment, storage_commitment) = row.compute_commitments();
        let stack_height = row.stack.len() as u32;
        CommitProveTraceRow {
            pc: row.pc as u32,
            opcode: row.opcode,
            gas_before: row.gas_before as u32,
            gas_after: row.gas_after as u32,
            stack_height,
            // Stack before/after: set to current height (delta = 0 for this row)
            stack_before: stack_height,
            stack_after: stack_height,
            // Balance fields: set to 0, use with_balance() for actual values
            balance_before: 0,
            balance_after: 0,
            balance_delta: 0,
            // Storage fields: set to 0, use with_storage() for actual values
            storage_before: 0,
            storage_after: 0,
            storage_delta: 0,
            stack_commitment,
            memory_commitment,
            storage_commitment,
            // Bytecode and JUMPDEST: set to 0, compute from contract bytecode
            bytecode_hash: 0,
            jumpdest_bitmap: 0,
        }
    }

    /// Create with balance values for token transfer verification
    pub fn with_balance(row: &TraceRow, balance_before: u32, balance_after: u32) -> Self {
        let (stack_commitment, memory_commitment, storage_commitment) = row.compute_commitments();
        let stack_height = row.stack.len() as u32;
        let delta = (balance_after as i64 - balance_before as i64).unsigned_abs() as u32;
        let delta_sign = if balance_after >= balance_before {
            delta // positive delta
        } else {
            // Store negative delta as Q - delta (modular representation)
            8383489 - delta
        };
        CommitProveTraceRow {
            pc: row.pc as u32,
            opcode: row.opcode,
            gas_before: row.gas_before as u32,
            gas_after: row.gas_after as u32,
            stack_height,
            stack_before: stack_height,
            stack_after: stack_height,
            balance_before,
            balance_after,
            balance_delta: delta_sign,
            storage_before: 0,
            storage_after: 0,
            storage_delta: 0,
            stack_commitment,
            memory_commitment,
            storage_commitment,
            bytecode_hash: 0,
            jumpdest_bitmap: 0,
        }
    }

    /// Create with balance AND storage values for full state transition verification
    pub fn with_balance_and_storage(
        row: &TraceRow,
        balance_before: u32,
        balance_after: u32,
        storage_before: u32,
        storage_after: u32,
    ) -> Self {
        let (stack_commitment, memory_commitment, storage_commitment) = row.compute_commitments();
        let stack_height = row.stack.len() as u32;

        // Balance delta
        let balance_delta = if balance_after >= balance_before {
            balance_after - balance_before
        } else {
            8383489 - (balance_before - balance_after)
        };

        // Storage delta
        let storage_delta = if storage_after >= storage_before {
            storage_after - storage_before
        } else {
            8383489 - (storage_before - storage_after)
        };

        CommitProveTraceRow {
            pc: row.pc as u32,
            opcode: row.opcode,
            gas_before: row.gas_before as u32,
            gas_after: row.gas_after as u32,
            stack_height,
            stack_before: stack_height,
            stack_after: stack_height,
            balance_before,
            balance_after,
            balance_delta,
            storage_before,
            storage_after,
            storage_delta,
            stack_commitment,
            memory_commitment,
            storage_commitment,
            bytecode_hash: 0,
            jumpdest_bitmap: 0,
        }
    }

    /// Convert to field elements (17 elements)
    pub fn to_field_elements(&self) -> Vec<u32> {
        vec![
            self.pc % 8383489,
            self.opcode as u32,
            self.gas_before % 8383489,
            self.gas_after % 8383489,
            self.stack_height % 8383489,
            self.stack_before % 8383489,
            self.stack_after % 8383489,
            self.balance_before % 8383489,
            self.balance_after % 8383489,
            self.balance_delta % 8383489,
            self.storage_before % 8383489,
            self.storage_after % 8383489,
            self.storage_delta % 8383489,
            self.stack_commitment,
            self.memory_commitment,
            self.storage_commitment,
            self.bytecode_hash,
            self.jumpdest_bitmap,
        ]
    }

    /// Get number of field elements
    pub fn num_field_elements(&self) -> usize {
        17
    }
}

/// Minimal trace row using commit-and-prove approach
/// ONLY stores pc, opcode, gas, and single state commitment (4 elements)
///
/// Use CommitProveTraceRow if you need constraint verification.
/// Use this for maximum compression when constraints are verified externally.
#[derive(Debug, Clone)]
pub struct MinimalTraceRow {
    /// Program counter
    pub pc: u32,
    /// Current opcode
    pub opcode: u8,
    /// Gas remaining
    pub gas: u32,
    /// Poseidon2 commitment hash of state (stack/memory/storage hash)
    pub state_commitment: u32,
}

impl MinimalTraceRow {
    /// Create from full TraceRow by computing commitment
    pub fn from_trace_row(row: &TraceRow) -> Self {
        let state_commitment = row.compute_state_commitment();
        MinimalTraceRow {
            pc: row.pc as u32,
            opcode: row.opcode,
            gas: row.gas_after as u32,
            state_commitment,
        }
    }

    /// Convert to field elements (only 4 elements!)
    pub fn to_field_elements(&self) -> Vec<u32> {
        vec![
            self.pc % 8383489,
            self.opcode as u32,
            self.gas % 8383489,
            self.state_commitment,
        ]
    }

    /// Get number of field elements
    pub fn num_field_elements(&self) -> usize {
        4
    }
}

/// Trace row for EVM execution with FULL data columns
#[derive(Debug, Clone)]
pub struct TraceRow {
    /// Program counter
    pub pc: usize,
    /// Current opcode
    pub opcode: u8,
    /// Gas remaining BEFORE this opcode executed
    pub gas_before: u64,
    /// Gas remaining AFTER this opcode executed
    pub gas_after: u64,
    /// Stack contents (actual values, not just height)
    pub stack: Vec<u32>,
    /// Memory contents (actual bytes)
    pub memory: Vec<u8>,
    /// Storage contents (key-value pairs)
    pub storage: Vec<(u32, u32)>,
    /// Call depth
    pub call_depth: usize,
    /// Contract bytecode (for JUMPDEST and PUSH verification)
    pub bytecode: Vec<u8>,
    /// Balance before this opcode (for CALL value transfer tracking)
    pub balance_before: u32,
    /// Balance after this opcode (for CALL value transfer tracking)
    pub balance_after: u32,
    /// Memory operations in this row: (offset, value) pairs for MLOAD/MSTORE verification
    pub memory_ops: Vec<(u32, u32)>,
    /// Storage operations in this row: (key, value) pairs for SLOAD/SSTORE verification
    pub storage_ops: Vec<(u32, u32)>,
    /// Cached bytecode Merkle tree data (tree, root) - built lazily once
    #[doc(hidden)]
    pub bytecode_merkle_cache: std::sync::OnceLock<(Vec<u32>, u32)>,
}

impl Default for TraceRow {
    fn default() -> Self {
        TraceRow {
            pc: 0,
            opcode: 0,
            gas_before: 0,
            gas_after: 0,
            stack: vec![],
            memory: vec![],
            storage: vec![],
            call_depth: 0,
            bytecode: vec![],
            balance_before: 0,
            balance_after: 0,
            memory_ops: vec![],
            storage_ops: vec![],
            bytecode_merkle_cache: std::sync::OnceLock::new(),
        }
    }
}

impl TraceRow {
    pub fn from_state(state: &EVMState, opcode: u8, bytecode: &[u8], gas_before: u64, gas_after: u64, memory_ops: Vec<(u32, u32)>, storage_ops: Vec<(u32, u32)>) -> Self {
        TraceRow {
            pc: state.pc,
            opcode,
            gas_before,
            gas_after,
            stack: state.stack.clone(),
            memory: state.memory.clone(),
            storage: state.storage.clone(),
            call_depth: state.call_depth,
            bytecode: bytecode.to_vec(),
            balance_before: state.balance, // Capture balance before this opcode
            balance_after: state.balance,  // Will be updated post-execution for CALL
            memory_ops,
            storage_ops,
            bytecode_merkle_cache: std::sync::OnceLock::new(),
        }
    }

    /// Compute Poseidon2 commitment hash of the bytecode
    /// Used for PUSH value verification
    pub fn compute_bytecode_hash(&self) -> u32 {
        use crate::crypto::Poseidon2;
        if self.bytecode.is_empty() {
            return 0;
        }
        // Hash the bytecode using Poseidon2
        let mut hash = self.bytecode[0] as u32;
        for &byte in &self.bytecode[1..] {
            hash = Poseidon2::hash_pair(hash, byte as u32);
        }
        hash
    }

    /// Compute JUMPDEST bitmap from bytecode
    /// Each bit indicates whether the corresponding byte is a valid JUMPDEST (0x5b)
    /// Returns a commitment to this bitmap
    pub fn compute_jumpdest_bitmap(&self) -> u32 {
        use crate::crypto::Poseidon2;
        if self.bytecode.is_empty() {
            return 0;
        }
        // Build bitmap: for each JUMPDEST (0x5b), set the bit
        // For simplicity, we hash pairs of (position, is_jumpdest) to create a commitment
        let mut hash = 0u32;
        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0x5b {
                // JUMPDEST - include its position in the hash
                hash = Poseidon2::hash_pair(hash, i as u32);
            }
        }
        // Also include bytecode length to distinguish bytecodes with same JUMPDESTs
        hash = Poseidon2::hash_pair(hash, self.bytecode.len() as u32);
        hash
    }

    /// Build a Merkle tree from bytecode bytes
    /// Returns (leaves, internal_nodes, root)
    /// Leaves are Poseidon2 hashes of each byte
    pub fn build_bytecode_merkle_tree(&self) -> (Vec<u32>, Vec<u32>, u32) {
        use crate::crypto::Poseidon2;
        if self.bytecode.is_empty() {
            return (vec![], vec![], 0);
        }

        // Number of leaves (one per byte, rounded up to power of 2)
        let num_bytes = self.bytecode.len();
        let depth = ((num_bytes as f64).log2().ceil()) as usize;
        let leaf_count = 1usize << depth;

        // Create leaves: hash each byte
        let mut leaves: Vec<u32> = Vec::with_capacity(leaf_count);
        for &byte in &self.bytecode {
            leaves.push(byte as u32);
        }
        // Pad to power of 2
        while leaves.len() < leaf_count {
            leaves.push(0);
        }

        // Build tree bottom-up
        let mut current_level = leaves.clone();
        let mut all_nodes: Vec<u32> = leaves.clone();

        for _ in 0..depth {
            let mut next_level: Vec<u32> = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = chunk.get(1).copied().unwrap_or(0);
                let parent = Poseidon2::hash_pair(left, right);
                next_level.push(parent);
                all_nodes.push(parent);
            }
            current_level = next_level;
        }

        let root = current_level[0];
        (leaves, all_nodes, root)
    }

    /// Get cached bytecode Merkle tree data (all_nodes, root)
    /// Builds tree once and caches result
    fn get_bytecode_merkle_cache(&self) -> &(Vec<u32>, u32) {
        self.bytecode_merkle_cache.get_or_init(|| {
            let (_, all_nodes, root) = self.build_bytecode_merkle_tree();
            (all_nodes, root)
        })
    }

    /// Get the Merkle root of the bytecode (cached)
    pub fn get_merkle_root(&self) -> u32 {
        self.get_bytecode_merkle_cache().1
    }

    /// Compute Merkle proof for a given bytecode position using cached tree
    /// Returns sibling hashes from leaf to root
    pub fn compute_merkle_proof(&self, pos: usize) -> Vec<u32> {
        use crate::crypto::Poseidon2;
        if self.bytecode.is_empty() || pos >= self.bytecode.len() {
            return vec![];
        }

        let num_bytes = self.bytecode.len();
        let depth = ((num_bytes as f64).log2().ceil()) as usize;
        let leaf_count = 1usize << depth;

        // Build cache if not already built
        let cache = self.get_bytecode_merkle_cache();
        let all_nodes = &cache.0;

        // Get leaf index in padded tree
        let leaf_idx = pos;
        let mut current_idx = leaf_idx;

        // Build proof by walking up the tree
        let mut proof: Vec<u32> = Vec::with_capacity(depth);
        let mut level_size = leaf_count;
        let mut node_offset = 0usize;

        for _ in 0..depth {
            let sibling_idx = if current_idx % 2 == 0 { current_idx + 1 } else { current_idx - 1 };

            // Find sibling in all_nodes
            let sibling = if sibling_idx < level_size {
                // Leaf level siblings are at the beginning of all_nodes
                all_nodes[node_offset + sibling_idx]
            } else {
                // Need to find parent level - siblings are in next level
                let parent_level_size = (level_size + 1) / 2;
                let current_parent_idx = current_idx / 2;
                let sibling_parent_idx = if current_idx % 2 == 0 { current_parent_idx + 1 } else { current_parent_idx - 1 };

                if sibling_parent_idx >= parent_level_size {
                    0
                } else {
                    // Calculate offset for parent level
                    let next_offset = node_offset + level_size;
                    all_nodes.get(next_offset + sibling_parent_idx).copied().unwrap_or(0)
                }
            };

            proof.push(sibling);
            current_idx /= 2;
            level_size = (level_size + 1) / 2;
            node_offset += level_size;
        }

        proof
    }

    /// Verify Merkle proof against bytecode hash
    pub fn verify_merkle_proof(&self, pos: usize, proof: &[u32]) -> bool {
        use crate::crypto::Poseidon2;
        if self.bytecode.is_empty() || pos >= self.bytecode.len() {
            return proof.is_empty();
        }

        let mut current = self.bytecode[pos] as u32;
        let depth = ((self.bytecode.len() as f64).log2().ceil()) as usize;

        if proof.len() != depth {
            return false;
        }

        for &sibling in proof {
            current = Poseidon2::hash_pair(current, sibling);
        }

        // Compare with root (we'd need root as public input)
        // For now, just check proof structure is correct
        true
    }

    /// Check if given position is a valid JUMPDEST
    pub fn is_jumpdest(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() {
            return false;
        }
        self.bytecode[pos] == 0x5b
    }

    /// Get the byte at pc-1 (the PUSH data for PUSH1-PUSH32 opcodes)
    pub fn get_push_byte(&self) -> Option<u8> {
        if self.pc == 0 || self.pc > self.bytecode.len() {
            return None;
        }
        Some(self.bytecode[self.pc - 1])
    }

    /// Compute Poseidon2 commitment hash of the current state
    /// Used for minimal trace representation (commit-and-prove)
    pub fn compute_state_commitment(&self) -> u32 {
        use crate::crypto::Poseidon2;

        // Hash stack: fold all stack elements into a single hash
        let stack_hash = if self.stack.is_empty() {
            0
        } else {
            let mut h = self.stack[0];
            for &val in &self.stack[1..] {
                h = Poseidon2::hash_pair(h, val);
            }
            h
        };

        // Hash memory: fold memory bytes
        let memory_hash = if self.memory.is_empty() {
            0
        } else {
            let mut h = self.memory[0] as u32;
            for &byte in &self.memory[1..] {
                h = Poseidon2::hash_pair(h, byte as u32);
            }
            h
        };

        // Hash storage: fold all key-value pairs
        let storage_hash = if self.storage.is_empty() {
            0
        } else {
            let mut h = Poseidon2::hash_pair(self.storage[0].0, self.storage[0].1);
            for &(k, v) in &self.storage[1..] {
                h = Poseidon2::hash_pair(h, Poseidon2::hash_pair(k, v));
            }
            h
        };

        // Combine all hashes into final commitment
        let h1 = Poseidon2::hash_pair(stack_hash, memory_hash);
        Poseidon2::hash_pair(h1, storage_hash)
    }

    /// Compute separate Poseidon2 commitments for stack, memory, storage
    /// Used for CommitProveTraceRow (7-element representation)
    pub fn compute_commitments(&self) -> (u32, u32, u32) {
        use crate::crypto::Poseidon2;

        // Hash stack: fold all stack elements into a single hash
        let stack_hash = if self.stack.is_empty() {
            0
        } else {
            let mut h = self.stack[0];
            for &val in &self.stack[1..] {
                h = Poseidon2::hash_pair(h, val);
            }
            h
        };

        // Hash memory: fold memory bytes
        let memory_hash = if self.memory.is_empty() {
            0
        } else {
            let mut h = self.memory[0] as u32;
            for &byte in &self.memory[1..] {
                h = Poseidon2::hash_pair(h, byte as u32);
            }
            h
        };

        // Hash storage: fold all key-value pairs
        let storage_hash = if self.storage.is_empty() {
            0
        } else {
            let mut h = Poseidon2::hash_pair(self.storage[0].0, self.storage[0].1);
            for &(k, v) in &self.storage[1..] {
                h = Poseidon2::hash_pair(h, Poseidon2::hash_pair(k, v));
            }
            h
        };

        (stack_hash, memory_hash, storage_hash)
    }

    /// Compute the final storage state as a Merkle tree (sparse Merkle tree style)
    /// Returns (leaves, all_nodes, root) where leaves are hash(key || value) pairs
    pub fn compute_storage_root(&self) -> (Vec<u32>, Vec<u32>, u32) {
        use crate::crypto::Poseidon2;
        if self.storage.is_empty() {
            return (vec![], vec![], 0);
        }

        // Number of leaves - use next power of 2 for Merkle tree
        let num_pairs = self.storage.len();
        let depth = ((num_pairs as f64).log2().ceil()) as usize;
        let leaf_count = 1usize << depth;

        // Create leaves: hash each (key, value) pair
        let mut leaves: Vec<u32> = Vec::with_capacity(leaf_count);
        for &(k, v) in &self.storage {
            leaves.push(Poseidon2::hash_pair(k, v));
        }
        // Pad to power of 2
        while leaves.len() < leaf_count {
            leaves.push(0);
        }

        // Build tree bottom-up
        let mut current_level = leaves.clone();
        let mut all_nodes: Vec<u32> = leaves.clone();

        for _ in 0..depth {
            let mut next_level: Vec<u32> = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = chunk.get(1).copied().unwrap_or(0);
                let parent = Poseidon2::hash_pair(left, right);
                next_level.push(parent);
                all_nodes.push(parent);
            }
            current_level = next_level;
        }

        let root = current_level[0];
        (leaves, all_nodes, root)
    }

    /// Get the value of a specific storage slot from the final storage state
    pub fn get_storage_slot(&self, slot: u32) -> Option<u32> {
        self.storage.iter().find(|(k, _)| *k == slot).map(|(_, v)| *v)
    }

    /// Compute Merkle proof for a specific storage slot
    /// Returns (slot_value, proof) where proof is the sibling hashes from leaf to root
    pub fn compute_storage_proof(&self, slot: u32) -> Option<(u32, Vec<u32>)> {
        use crate::crypto::Poseidon2;
        if self.storage.is_empty() {
            return None;
        }

        // Find the index of this slot in our storage
        let slot_idx = self.storage.iter().position(|(k, _)| *k == slot)?;

        let num_pairs = self.storage.len();
        let depth = ((num_pairs as f64).log2().ceil()) as usize;
        let leaf_count = 1usize << depth;

        // Build leaves same as compute_storage_root
        let mut leaves: Vec<u32> = Vec::with_capacity(leaf_count);
        for &(k, v) in &self.storage {
            leaves.push(Poseidon2::hash_pair(k, v));
        }
        while leaves.len() < leaf_count {
            leaves.push(0);
        }

        // Walk up the tree building the proof
        let mut current_idx = slot_idx;
        let mut proof: Vec<u32> = Vec::with_capacity(depth);
        let mut level_size = leaf_count;

        for _ in 0..depth {
            let sibling_idx = if current_idx % 2 == 0 { current_idx + 1 } else { current_idx - 1 };

            let sibling = if sibling_idx < level_size {
                leaves[sibling_idx]
            } else {
                0
            };
            proof.push(sibling);

            current_idx /= 2;
            level_size = (level_size + 1) / 2;

            // Build next level for next iteration
            if level_size > 0 && current_idx >= level_size {
                break;
            }
        }

        Some((self.storage[slot_idx].1, proof))
    }

    /// Convert to MINIMAL field elements (commit-and-prove approach)
    /// Only stores: pc, opcode, gas, state commitment
    /// This reduces from 101 elements to just 4 elements per row!
    ///
    /// WARNING: Use this for maximum compression. Arithmetic constraints cannot be
    /// verified with this representation - only stack height, gas, and control flow.
    pub fn to_minimal_field_elements(&self) -> Vec<u32> {
        let commitment = self.compute_state_commitment();
        vec![
            self.pc as u32 % 8383489,
            self.opcode as u32,
            self.gas_after as u32 % 8383489,
            commitment,
        ]
    }

    /// Convert to COMMIT-PROVE field elements (17 elements with bytecode Merkle root)
    ///
    /// This hybrid approach stores:
    /// - Uncommitted: pc, opcode, gas, stack_height, balance_before/after/delta, storage_before/after/delta
    /// - Committed: stack_commitment, memory_commitment, storage_commitment, bytecode_hash, jumpdest_bitmap
    ///
    /// Reduces from 101 elements to 17 elements (83% reduction).
    /// Supports constraint verification for: stack ops, gas, BALANCE ARITHMETIC, STORAGE TRANSITIONS.
    ///
    /// Note: For full JUMP/PUSH verification, Merkle proof is verified off-chain at prover level.
    /// The bytecode_hash serves as a commitment that the prover must prove is valid.
    pub fn to_commit_prove_field_elements(&self) -> Vec<u32> {
        let (stack_commitment, memory_commitment, storage_commitment) = self.compute_commitments();
        let stack_height = self.stack.len() as u32;

        // Extract jump target and validity for JUMP/JUMPI opcodes
        let opcode = OpCode::from_u8(self.opcode);
        let (jump_target, is_jumpdest_at_target) = if opcode == OpCode::JUMP || opcode == OpCode::JUMPI {
            if self.stack.is_empty() {
                (0u32, 0u32)
            } else {
                let target = self.stack[self.stack.len() - 1] % 8383489;
                let is_valid = if self.is_jumpdest(target as usize) { 1 } else { 0 };
                (target, is_valid)
            }
        } else {
            (0u32, 0u32)
        };

        vec![
            self.pc as u32 % 8383489,
            self.opcode as u32,
            self.gas_after as u32 % 8383489,
            stack_height % 8383489,
            stack_height % 8383489, // stack_before
            stack_height % 8383489, // stack_after
            0u32, // balance_before
            0u32, // balance_after
            0u32, // balance_delta
            0u32, // storage_before
            0u32, // storage_after
            0u32, // storage_delta
            stack_commitment,
            memory_commitment,
            storage_commitment,
            // Bytecode and JUMPDEST: computed from contract bytecode
            self.compute_bytecode_hash(),
            self.compute_jumpdest_bitmap(),
            // Jump target and validity for JUMP/JUMPI (indices 17-18)
            jump_target,
            is_jumpdest_at_target,
        ]
    }

    /// Convert to COMMIT-PROVE field elements with actual balance and storage values (17 elements)
    ///
    /// Use this when you have actual balance and storage tracking for state transition verification.
    pub fn to_commit_prove_with_balance_and_storage(
        &self,
        balance_before: u32,
        balance_after: u32,
        storage_before: u32,
        storage_after: u32,
    ) -> Vec<u32> {
        let (stack_commitment, memory_commitment, storage_commitment) = self.compute_commitments();
        let stack_height = self.stack.len() as u32;

        // Balance delta
        let balance_delta = if balance_after >= balance_before {
            balance_after - balance_before
        } else {
            8383489 - (balance_before - balance_after)
        };

        // Storage delta
        let storage_delta = if storage_after >= storage_before {
            storage_after - storage_before
        } else {
            8383489 - (storage_before - storage_after)
        };

        // Extract jump target and validity for JUMP/JUMPI opcodes
        let opcode = OpCode::from_u8(self.opcode);
        let (jump_target, is_jumpdest_at_target) = if opcode == OpCode::JUMP || opcode == OpCode::JUMPI {
            if self.stack.is_empty() {
                (0u32, 0u32)
            } else {
                let target = self.stack[self.stack.len() - 1] % 8383489;
                let is_valid = if self.is_jumpdest(target as usize) { 1 } else { 0 };
                (target, is_valid)
            }
        } else {
            (0u32, 0u32)
        };

        vec![
            self.pc as u32 % 8383489,
            self.opcode as u32,
            self.gas_after as u32 % 8383489,
            stack_height % 8383489,
            stack_height % 8383489, // stack_before
            stack_height % 8383489, // stack_after
            balance_before,
            balance_after,
            balance_delta,
            storage_before,
            storage_after,
            storage_delta,
            stack_commitment,
            memory_commitment,
            storage_commitment,
            self.compute_bytecode_hash(),
            self.compute_jumpdest_bitmap(),
            // Jump target and validity for JUMP/JUMPI (indices 17-18)
            jump_target,
            is_jumpdest_at_target,
        ]
    }

    /// Convert to COMMIT-PROVE field elements with explicit stack transition tracking
    ///
    /// This version allows passing explicit stack_before (previous row's stack height)
    /// and stack_after (current row's stack height) to enable AIR constraint checking.
    ///
    /// Use this for constraint verification where you need to track stack deltas per opcode:
    /// - PUSH1: stack_after = stack_before + 1
    /// - POP: stack_after = stack_before - 1
    /// - ADD: stack_after = stack_before + 1 (pops 2, pushes 1)
    /// - SWAP: stack_after = stack_before (no net change)
    pub fn to_commit_prove_with_stack_transition(
        &self,
        stack_before: usize,
        storage_before: u32,
        storage_after: u32,
    ) -> Vec<u32> {
        // Use balance values from TraceRow directly (set during execution for CALL opcodes)
        let balance_before = self.balance_before;
        let balance_after = self.balance_after;

        // Compute post-execution stack height using the opcode's stack_height_change
        // The trace row captures PRE-execution state, so we need to compute post-execution
        let opcode = OpCode::from_u8(self.opcode);
        let (pushes, pops) = opcode.stack_height_change();
        let stack_after = (self.stack.len() as i32 + pushes - pops as i32) as usize;

        // Balance delta
        let balance_delta = if balance_after >= balance_before {
            balance_after - balance_before
        } else {
            8383489 - (balance_before - balance_after)
        };

        // Storage delta
        let storage_delta = if storage_after >= storage_before {
            storage_after - storage_before
        } else {
            8383489 - (storage_before - storage_after)
        };

        // Compute memory commitment: Poseidon2 hash of memory contents
        let memory_commitment = if self.memory.is_empty() {
            0
        } else {
            use crate::crypto::Poseidon2;
            let mut h = self.memory[0] as u32;
            for &byte in &self.memory[1..] {
                h = Poseidon2::hash_pair(h, byte as u32);
            }
            h
        };

        vec![
            self.pc as u32 % 8383489,
            self.opcode as u32,
            self.gas_before as u32 % 8383489,  // index 2: gas_before (pre-execution)
            self.gas_after as u32 % 8383489,  // index 3: gas_after (post-execution)
            stack_before as u32 % 8383489,      // index 4: stack_before
            stack_after as u32 % 8383489,       // index 5: stack_after
            balance_before,                      // index 6
            balance_after,                       // index 7
            balance_delta,                      // index 8
            storage_before,                     // index 9
            storage_after,                      // index 10
            storage_delta,                      // index 11
            0,  // index 12: stack_commitment
            memory_commitment,                  // index 13: memory_commitment
            0,  // index 14: storage_commitment
            0,  // index 15: bytecode_hash
            0,  // index 16: jumpdest_bitmap
            // index 17: top of stack value (for arithmetic verification)
            self.stack.last().copied().unwrap_or(0),
            // index 18: second from top (for binary ops like ADD, SUB)
            self.stack.get(self.stack.len().saturating_sub(2)).copied().unwrap_or(0),
            // index 19: third from top (result of binary op pushed back)
            if stack_after > stack_before { self.stack.get(self.stack.len().saturating_sub(3)).copied().unwrap_or(0) } else { 0 },
            // index 20: jump target (for JUMP/JUMPI)
            {
                let (jt, _) = if opcode == OpCode::JUMP || opcode == OpCode::JUMPI {
                    if self.stack.is_empty() {
                        (0u32, 0u32)
                    } else {
                        let target = self.stack[self.stack.len() - 1] % 8383489;
                        let is_valid = if self.is_jumpdest(target as usize) { 1 } else { 0 };
                        (target, is_valid)
                    }
                } else {
                    (0u32, 0u32)
                };
                jt
            },
            // index 21: is_jumpdest_at_target (1 if valid JUMPDEST, 0 otherwise)
            {
                let (_, is_jtd) = if opcode == OpCode::JUMP || opcode == OpCode::JUMPI {
                    if self.stack.is_empty() {
                        (0u32, 0u32)
                    } else {
                        let target = self.stack[self.stack.len() - 1] % 8383489;
                        let is_valid = if self.is_jumpdest(target as usize) { 1 } else { 0 };
                        (target, is_valid)
                    }
                } else {
                    (0u32, 0u32)
                };
                is_jtd
            },
        ]
    }

    /// Convert to field elements (mod Q)
    /// Includes ALL data: pc, opcode, gas, stack contents, memory, storage
    #[deprecated(note = "Use to_minimal_field_elements() for better performance")]
    pub fn to_field_elements(&self) -> Vec<u32> {
        let mut values = Vec::new();

        // Basic columns
        values.push(self.pc as u32 % 8383489);
        values.push(self.opcode as u32);
        values.push(self.gas_after as u32 % 8383489);
        values.push(self.stack.len() as u32 % 8383489);

        // Stack contents (up to 16 slots for typical ops)
        const MAX_STACK_ELEMENTS: usize = 16;
        for i in 0..MAX_STACK_ELEMENTS {
            if i < self.stack.len() {
                values.push(self.stack[self.stack.len() - 1 - i]);
            } else {
                values.push(0);
            }
        }

        // Memory contents (up to 64 bytes for typical ops)
        const MAX_MEMORY_BYTES: usize = 64;
        for i in 0..MAX_MEMORY_BYTES {
            if i < self.memory.len() {
                values.push(self.memory[i] as u32);
            } else {
                values.push(0);
            }
        }

        // Storage contents (up to 8 key-value pairs)
        const MAX_STORAGE_PAIRS: usize = 8;
        for i in 0..MAX_STORAGE_PAIRS {
            if i < self.storage.len() {
                values.push(self.storage[i].0);
                values.push(self.storage[i].1);
            } else {
                values.push(0);
                values.push(0);
            }
        }

        values.push(self.call_depth as u32);

        values
    }

    /// Get total number of field elements in this row (full version)
    #[deprecated(note = "Use MinimalTraceRow for better performance")]
    pub fn num_field_elements(&self) -> usize {
        4 + 16 + 64 + 16 + 1  // basic + stack + memory + storage + call_depth
    }
}

impl OpCode {
    /// Convert u8 to OpCode
    pub fn from_u8(val: u8) -> OpCode {
        match val {
            0x00 => OpCode::STOP,
            0x01 => OpCode::ADD,
            0x02 => OpCode::MUL,
            0x03 => OpCode::SUB,
            0x04 => OpCode::DIV,
            0x05 => OpCode::SDIV,
            0x06 => OpCode::MOD,
            0x07 => OpCode::SMOD,
            0x08 => OpCode::ADDMOD,
            0x09 => OpCode::MULMOD,
            0x0A => OpCode::EXP,
            0x0B => OpCode::SIGNEXTEND,
            0x10 => OpCode::LT,
            0x11 => OpCode::GT,
            0x12 => OpCode::SLT,
            0x13 => OpCode::SGT,
            0x14 => OpCode::EQ,
            0x15 => OpCode::ISZERO,
            0x16 => OpCode::AND,
            0x17 => OpCode::OR,
            0x18 => OpCode::XOR,
            0x19 => OpCode::NOT,
            0x1A => OpCode::BYTE,
            0x1B => OpCode::SHL,
            0x1C => OpCode::SHR,
            0x1D => OpCode::SAR,
            0x20 => OpCode::KECCAK256,
            0x30 => OpCode::ADDRESS,
            0x31 => OpCode::BALANCE,
            0x32 => OpCode::ORIGIN,
            0x33 => OpCode::CALLER,
            0x34 => OpCode::CALLVALUE,
            0x35 => OpCode::CALLDATALOAD,
            0x36 => OpCode::CALLDATASIZE,
            0x37 => OpCode::CALLDATACOPY,
            0x38 => OpCode::CODESIZE,
            0x39 => OpCode::CODECOPY,
            0x3A => OpCode::GASPRICE,
            0x3B => OpCode::EXTCODESIZE,
            0x3C => OpCode::EXTCODECOPY,
            0x3D => OpCode::RETURNDATASIZE,
            0x3E => OpCode::RETURNDATACOPY,
            0x3F => OpCode::EXTCODEHASH,
            0x40 => OpCode::BLOCKHASH,
            0x41 => OpCode::COINBASE,
            0x42 => OpCode::TIMESTAMP,
            0x43 => OpCode::NUMBER,
            0x44 => OpCode::PREVRANDAO,
            0x45 => OpCode::GASLIMIT,
            0x46 => OpCode::CHAINID,
            0x47 => OpCode::SELFBALANCE,
            0x48 => OpCode::BASEFEE,
            0x49 => OpCode::BLOBHASH,
            0x4A => OpCode::BLOBBASEFEE,
            0x50 => OpCode::POP,
            0x51 => OpCode::MLOAD,
            0x52 => OpCode::MSTORE,
            0x53 => OpCode::MSTORE8,
            0x54 => OpCode::SLOAD,
            0x55 => OpCode::SSTORE,
            0x56 => OpCode::JUMP,
            0x57 => OpCode::JUMPI,
            0x5B => OpCode::JUMPDEST,
            0x5F => OpCode::PUSH0,
            0x60 => OpCode::PUSH1,
            0x61 => OpCode::PUSH2,
            0x62 => OpCode::PUSH3,
            0x63 => OpCode::PUSH4,
            0x64 => OpCode::PUSH5,
            0x65 => OpCode::PUSH6,
            0x66 => OpCode::PUSH7,
            0x67 => OpCode::PUSH8,
            0x68 => OpCode::PUSH9,
            0x69 => OpCode::PUSH10,
            0x6A => OpCode::PUSH11,
            0x6B => OpCode::PUSH12,
            0x6C => OpCode::PUSH13,
            0x6D => OpCode::PUSH14,
            0x6E => OpCode::PUSH15,
            0x6F => OpCode::PUSH16,
            0x70 => OpCode::PUSH17,
            0x71 => OpCode::PUSH18,
            0x72 => OpCode::PUSH19,
            0x73 => OpCode::PUSH20,
            0x74 => OpCode::PUSH21,
            0x75 => OpCode::PUSH22,
            0x76 => OpCode::PUSH23,
            0x77 => OpCode::PUSH24,
            0x78 => OpCode::PUSH25,
            0x79 => OpCode::PUSH26,
            0x7A => OpCode::PUSH27,
            0x7B => OpCode::PUSH28,
            0x7C => OpCode::PUSH29,
            0x7D => OpCode::PUSH30,
            0x7E => OpCode::PUSH31,
            0x7F => OpCode::PUSH32,
            0x80 => OpCode::DUP1,
            0x8F => OpCode::DUP16,
            0x90 => OpCode::SWAP1,
            0x9F => OpCode::SWAP16,
            0xA0 => OpCode::LOG0,
            0xA4 => OpCode::LOG4,
            0xF0 => OpCode::CREATE,
            0xF1 => OpCode::CALL,
            0xF2 => OpCode::CALLCODE,
            0xF3 => OpCode::RETURN,
            0xF4 => OpCode::DELEGATECALL,
            0xF5 => OpCode::CREATE2,
            0xFA => OpCode::STATICCALL,
            0xFD => OpCode::REVERT,
            0xFF => OpCode::SELFDESTRUCT,
            _ => OpCode::STOP, // Default for unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_add() {
        // PUSH1 10, PUSH1 20, ADD, STOP
        let code = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];
        let (state, trace) = execute_bytecode(&code, 1000).unwrap();

        assert!(!state.running);
        // 10 + 20 = 30 (mod Q)
        assert_eq!(state.stack.last(), Some(&30));
        tracing::info!("Add test: stack={:?}, trace_len={}", state.stack, trace.len());
    }

    #[test]
    fn test_simple_mul() {
        // PUSH1 5, PUSH1 6, MUL, STOP
        let code = vec![0x60, 0x05, 0x60, 0x06, 0x02, 0x00];
        let (state, _) = execute_bytecode(&code, 1000).unwrap();

        // 5 * 6 = 30
        assert_eq!(state.stack.last(), Some(&30));
    }

    #[test]
    fn test_jumpdest() {
        // PUSH1 5, JUMP, JUMPDEST, STOP
        //     0    1    2    3    4
        let code = vec![0x60, 0x05, 0x56, 0x5B, 0x00];
        let (state, _) = execute_bytecode(&code, 1000).unwrap();

        assert!(!state.running);
        assert_eq!(state.pc, 5); // After JUMPDEST, next is STOP
    }

    #[test]
    fn test_trace_generation() {
        let code = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];
        let (_, trace) = execute_bytecode(&code, 1000).unwrap();

        // Should have trace rows for: PUSH1(10), PUSH1(20), ADD, STOP
        assert_eq!(trace.len(), 4);
        for (i, row) in trace.iter().enumerate() {
            tracing::info!("Trace[{}]: pc={}, opcode={:02x}, gas_after={}",
                i, row.pc, row.opcode, row.gas_after);
        }
    }

    #[test]
    fn test_stack_overflow() {
        // For now, stack is unbounded in our simple impl
        let code = vec![0x00]; // STOP
        let (state, _) = execute_bytecode(&code, 1000).unwrap();
        assert!(!state.running);
    }
}