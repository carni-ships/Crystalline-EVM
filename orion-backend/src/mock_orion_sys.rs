//! Mock Orion FFI for Testing
//!
//! This module provides mock implementations of the Orion FFI functions,
//! allowing tests to run without the actual Orion library.
//!
//! Enable with feature flag: `cargo test --features mock`

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Types (match orion-sys)
// ============================================================================

pub type size_t = usize;
pub type int8_t = i8;
pub type uint8_t = u8;
pub type int16_t = i16;
pub type uint16_t = u16;
pub type int32_t = i32;
pub type uint32_t = u32;
pub type int64_t = i64;
pub type uint64_t = u64;
pub type f32 = std::ffi::c_float;

// Opaque Types
pub struct O_RIONGPUContext {
    mock_gpu_available: bool,
}

pub struct OrionANEContext {
    mock_initialized: bool,
}

// Constants
pub const LATTICEZK_K: uint32_t = 4;
pub const LATTICEZK_L: uint32_t = 256;
pub const LATTICEZK_N: uint32_t = 256;
pub const LATTICEZK_Q: uint32_t = 8383489;
pub const GPU_NTT_N: usize = 256;

// Types
#[repr(C)]
#[derive(Default)]
pub struct GPUNTTPoly {
    pub coeff: [uint32_t; GPU_NTT_N],
}

#[repr(C)]
pub struct RNSMod {
    pub mod_: uint32_t,
    pub name: *const std::ffi::c_char,
}

#[repr(C)]
pub struct TileLayout {
    pub n_tiles: int32_t,
    pub tile_size: int32_t,
    pub last_tile_size: int32_t,
    pub tile_offsets: *mut int32_t,
}

#[repr(C)]
pub struct LatticeZKRNSConfig {
    pub n_mods: int32_t,
    pub mods: *const RNSMod,
    pub product: uint64_t,
    pub bits: f64,
}

#[repr(C)]
pub struct LatticeZKTranscript {
    pub buffer: [uint8_t; 1024],
    pub len: size_t,
}

#[repr(C)]
#[derive(Default)]
pub struct LatticeZKProvingKey {
    pub seed: [uint8_t; 32],
    pub q: uint64_t,
    pub k: int32_t,
    pub l: int32_t,
    pub n: int32_t,
}

#[repr(C)]
#[derive(Default)]
pub struct LatticeZKVerificationKey {
    pub q: uint64_t,
    pub k: int32_t,
    pub l: int32_t,
    pub n: int32_t,
}

#[repr(C)]
#[derive(Default)]
pub struct LatticeZKProof {
    pub commitment: [uint8_t; 32],
    pub challenge: [uint8_t; 32],
    pub response: [uint64_t; 4],
}

// ============================================================================
// Mock State
// ============================================================================

static MOCK_GPU_AVAILABLE: AtomicU32 = AtomicU32::new(1);
static MOCK_MATVEC_CALL_COUNT: AtomicU32 = AtomicU32::new(0);
static MOCK_NTT_CALL_COUNT: AtomicU32 = AtomicU32::new(0);
static MOCK_CRT_CALL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Reset all mock state
pub fn reset_mock_state() {
    MOCK_GPU_AVAILABLE.store(1, Ordering::SeqCst);
    MOCK_MATVEC_CALL_COUNT.store(0, Ordering::SeqCst);
    MOCK_NTT_CALL_COUNT.store(0, Ordering::SeqCst);
    MOCK_CRT_CALL_COUNT.store(0, Ordering::SeqCst);
}

/// Set GPU availability
pub fn set_mock_gpu_available(available: bool) {
    MOCK_GPU_AVAILABLE.store(available as u32, Ordering::SeqCst);
}

/// Get call counts for verification
pub fn get_matvec_call_count() -> u32 {
    MOCK_MATVEC_CALL_COUNT.load(Ordering::SeqCst)
}

pub fn get_ntt_call_count() -> u32 {
    MOCK_NTT_CALL_COUNT.load(Ordering::SeqCst)
}

pub fn get_crt_call_count() -> u32 {
    MOCK_CRT_CALL_COUNT.load(Ordering::SeqCst)
}

// ============================================================================
// ANE Runtime
// ============================================================================

#[no_mangle]
pub extern "C" fn orion_ane_init() -> *mut OrionANEContext {
    let ctx = Box::new(OrionANEContext { mock_initialized: true });
    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "C" fn orion_ane_release(_ctx: *mut OrionANEContext) {
    if !_ctx.is_null() {
        unsafe { Box::from_raw(_ctx) };
    }
}

#[no_mangle]
pub extern "C" fn orion_compile_mil(
    _ctx: *mut OrionANEContext,
    _mil_program: *const std::ffi::c_char,
    _output: *mut std::ffi::c_void,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn orion_eval(
    _ctx: *mut OrionANEContext,
    _program: *mut std::ffi::c_void,
    _input_buf: *const std::ffi::c_void,
    _input_len: size_t,
    _output_buf: *mut std::ffi::c_void,
    _output_len: size_t,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn orion_eval_async(
    _ctx: *mut OrionANEContext,
    _program: *mut std::ffi::c_void,
    _input_buf: *const std::ffi::c_void,
    _input_len: size_t,
    _output_buf: *mut std::ffi::c_void,
    _output_len: size_t,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn orion_patch_weights(
    _program: *mut std::ffi::c_void,
    _weights: *const f32,
    _n_weights: size_t,
) -> bool {
    true
}

// ============================================================================
// GPU NTT
// ============================================================================

static MOCK_GPU_CONTEXT: std::sync::OnceLock<O_RIONGPUContext> = std::sync::OnceLock::new();

#[no_mangle]
pub extern "C" fn orion_gpu_init() -> *mut O_RIONGPUContext {
    if MOCK_GPU_AVAILABLE.load(Ordering::SeqCst) == 1 {
        MOCK_GPU_CONTEXT.get_or_init(|| O_RIONGPUContext { mock_gpu_available: true });
        MOCK_GPU_CONTEXT.get() as *const _ as *mut _
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn orion_gpu_release(_ctx: *mut O_RIONGPUContext) {}

#[no_mangle]
pub extern "C" fn orion_ntt_forward(
    _ctx: *mut O_RIONGPUContext,
    input: *const GPUNTTPoly,
    output: *mut GPUNTTPoly,
) -> bool {
    MOCK_NTT_CALL_COUNT.fetch_add(1, Ordering::SeqCst);

    if input.is_null() || output.is_null() {
        return false;
    }

    unsafe {
        let input_poly = &*input;
        let output_poly = &mut *output;

        for i in 0..GPU_NTT_N {
            output_poly.coeff[i] = input_poly.coeff[i].wrapping_mul(2).wrapping_add(1) % LATTICEZK_Q;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn orion_ntt_inverse(
    _ctx: *mut O_RIONGPUContext,
    input: *const GPUNTTPoly,
    output: *mut GPUNTTPoly,
) -> bool {
    if input.is_null() || output.is_null() {
        return false;
    }

    unsafe {
        let input_poly = &*input;
        let output_poly = &mut *output;

        for i in 0..GPU_NTT_N {
            output_poly.coeff[i] = input_poly.coeff[i];
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn orion_ntt_multiply(
    _ctx: *mut O_RIONGPUContext,
    a: *const GPUNTTPoly,
    b: *const GPUNTTPoly,
    result: *mut GPUNTTPoly,
) -> bool {
    if a.is_null() || b.is_null() || result.is_null() {
        return false;
    }

    unsafe {
        let a_poly = &*a;
        let b_poly = &*b;
        let result_poly = &mut *result;

        for i in 0..GPU_NTT_N {
            let prod = (a_poly.coeff[i] as u64) * (b_poly.coeff[i] as u64);
            result_poly.coeff[i] = (prod % (LATTICEZK_Q as u64)) as u32;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn orion_ntt_forward_batch(
    _ctx: *mut O_RIONGPUContext,
    _inputs: *const GPUNTTPoly,
    _outputs: *mut GPUNTTPoly,
    _count: int32_t,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn orion_gpu_device_name(_ctx: *mut O_RIONGPUContext) -> *const std::ffi::c_char {
    "MockMetal GPU\0".as_ptr() as *const std::ffi::c_char
}

#[no_mangle]
pub extern "C" fn orion_gpu_available() -> bool {
    MOCK_GPU_AVAILABLE.load(Ordering::SeqCst) == 1
}

// ============================================================================
// LatticeZK
// ============================================================================

#[no_mangle]
pub extern "C" fn latticezk_rns_config() -> *const LatticeZKRNSConfig {
    std::ptr::null()
}

#[no_mangle]
pub extern "C" fn latticezk_matvec(
    _A: *const f32,
    _s: *const f32,
    k: int32_t,
    _l: int32_t,
    _q: uint64_t,
    result: *mut uint64_t,
) -> bool {
    MOCK_MATVEC_CALL_COUNT.fetch_add(1, Ordering::SeqCst);

    if result.is_null() {
        return false;
    }

    unsafe {
        for i in 0..k as isize {
            if i < 4 {
                let ptr = result.cast::<u64>();
                *ptr.add(i as usize) = (i + 1) as u64 * 12345;
            }
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn latticezk_rns_matvec(
    _A: *const f32,
    _s: *const f32,
    _k: int32_t,
    _l: int32_t,
    _residues_out: *mut f32,
    _n_mods: int32_t,
    _rns: *const LatticeZKRNSConfig,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn latticezk_crt_reconstruct(
    residues: *const f32,
    _k: int32_t,
    _rns: *const LatticeZKRNSConfig,
    _q: uint64_t,
    result: *mut uint64_t,
) {
    MOCK_CRT_CALL_COUNT.fetch_add(1, Ordering::SeqCst);

    if residues.is_null() || result.is_null() {
        return;
    }

    unsafe {
        let mut sum: u64 = 0;
        for i in 0..4 {
            sum = sum.wrapping_add((i + 1) as u64 * 1000);
        }
        *result = sum % (_q as u64);
    }
}

#[no_mangle]
pub extern "C" fn latticezk_keygen(
    _seed: *const uint8_t,
    pk: *mut LatticeZKProvingKey,
    vk: *mut LatticeZKVerificationKey,
) {
    if !pk.is_null() {
        unsafe {
            let pk_mut = &mut *pk;
            pk_mut.q = LATTICEZK_Q as u64;
            pk_mut.k = LATTICEZK_K as i32;
            pk_mut.l = LATTICEZK_L as i32;
            pk_mut.n = LATTICEZK_N as i32;
        }
    }
    if !vk.is_null() {
        unsafe {
            let vk_mut = &mut *vk;
            vk_mut.q = LATTICEZK_Q as u64;
            vk_mut.k = LATTICEZK_K as i32;
            vk_mut.l = LATTICEZK_L as i32;
            vk_mut.n = LATTICEZK_N as i32;
        }
    }
}

#[no_mangle]
pub extern "C" fn latticezk_sign(
    _pk: *const LatticeZKProvingKey,
    _m: *const uint8_t,
    _m_len: size_t,
    _signature: *mut uint8_t,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn latticezk_verify_sig(
    _vk: *const LatticeZKVerificationKey,
    _m: *const uint8_t,
    _m_len: size_t,
    _signature: *const uint8_t,
) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn latticezk_transcript_init(_t: *mut LatticeZKTranscript) {}

#[no_mangle]
pub extern "C" fn latticezk_transcript_append(
    _t: *mut LatticeZKTranscript,
    _data: *const uint8_t,
    _len: size_t,
) {
}

#[no_mangle]
pub extern "C" fn latticezk_transcript_append_field(
    _t: *mut LatticeZKTranscript,
    _val: uint64_t,
    _q: uint64_t,
) {
}

#[no_mangle]
pub extern "C" fn latticezk_challenge_from_transcript(
    _t: *mut LatticeZKTranscript,
    _challenge: *mut uint8_t,
) {
}

// ============================================================================
// RNS Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn orion_extended_gcd(
    _a: int64_t,
    _b: int64_t,
    _x: *mut int64_t,
    _y: *mut int64_t,
) -> int64_t {
    1
}

#[no_mangle]
pub extern "C" fn orion_crt_reconstruct(
    _residues: *const uint32_t,
    _mods: *const RNSMod,
    _n: int32_t,
) -> uint64_t {
    42
}

#[no_mangle]
pub extern "C" fn orion_rns_product(_mods: *const RNSMod, _n: int32_t) -> uint64_t {
    1_000_000_007_u64
}

#[no_mangle]
pub extern "C" fn orion_rns_bits(_mods: *const RNSMod, _n: int32_t) -> f64 {
    30.0
}

#[no_mangle]
pub extern "C" fn orion_rns_decompose(
    _x: uint64_t,
    _mods: *const RNSMod,
    _n: int32_t,
    _residues_out: *mut uint32_t,
) {
}

#[no_mangle]
pub extern "C" fn orion_tile_layout_init(_tile: *mut TileLayout, _dim: int32_t, _max_tile: int32_t) {}

#[no_mangle]
pub extern "C" fn orion_tile_layout_free(_tile: *mut TileLayout) {}

#[no_mangle]
pub extern "C" fn orion_tile_size_at(_tile: *const TileLayout, _idx: int32_t) -> int32_t {
    32
}

#[no_mangle]
pub extern "C" fn orion_tile_offset_at(_tile: *const TileLayout, _idx: int32_t) -> int32_t {
    _idx * 32
}
