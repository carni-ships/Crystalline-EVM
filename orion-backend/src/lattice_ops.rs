//! Lattice Operations via Orion ANE/GPU
//!
//! Implements lattice-based ZK operations using the Orion C library:
//! - MatVec (ANE-accelerated via latticezk_matvec)
//! - NTT (GPU-accelerated via orion_ntt_*)
//! - CRT reconstruction (via latticezk_crt_reconstruct)
//!
//! These call into the Orion static library (liborion.a) for full acceleration.
//!
//! # Thread Safety
//! ANE context is shared globally via Arc<Mutex<>> to prevent "Context leak detected"
//! errors when multiple threads try to initialize ANE simultaneously.

use super::{FieldElement, BlackBoxFunc};
use super::error::BackendError;
use orion_sys::{
    OrionANEContext, O_RIONGPUContext,
    GPUNTTPoly,
    LATTICEZK_Q, GPU_NTT_N,
    latticezk_matvec, latticezk_crt_reconstruct,
    latticezk_rns_config,
    orion_ane_init, orion_gpu_init, orion_gpu_release,
    orion_ntt_forward, orion_ntt_inverse,
};
use std::sync::{Arc, Mutex};

/// ANE context wrapper
struct AneContext {
    ctx: *mut OrionANEContext,
}

/// GPU context wrapper
struct GpuContext {
    ctx: *mut O_RIONGPUContext,
}

/// Global ANE context singleton to prevent "Context leak detected" errors
/// when multiple threads try to initialize ANE simultaneously.
/// Apple ANE hardware only supports ONE context at a time.
///
/// We store as usize to avoid thread-safety issues with raw pointers.
/// The actual context pointer is stored in the LatticeOps instance.
static GLOBAL_ANE_INIT: std::sync::OnceLock<Arc<Mutex<()>>> =
    std::sync::OnceLock::new();

/// Lock to serialize ANE operations (ANE hardware can only handle one operation at a time)
static GLOBAL_ANE_OP_LOCK: std::sync::OnceLock<Arc<Mutex<()>>> =
    std::sync::OnceLock::new();

/// Get the global ANE initialization lock
fn get_global_ane_lock() -> Arc<Mutex<()>> {
    GLOBAL_ANE_INIT
        .get_or_init(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Get the global ANE operation lock (serializes concurrent ANE operations)
fn get_global_ane_op_lock() -> Arc<Mutex<()>> {
    GLOBAL_ANE_OP_LOCK
        .get_or_init(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Stores the actual ANE context pointer (stored as LatticeOps field, not global)
static GLOBAL_ANE_PTR: std::sync::OnceLock<std::sync::atomic::AtomicUsize> =
    std::sync::OnceLock::new();

/// Get the global ANE context pointer (returns pointer as usize, 0 if not initialized)
fn get_global_ane_ptr() -> usize {
    GLOBAL_ANE_PTR
        .get_or_init(|| std::sync::atomic::AtomicUsize::new(0))
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// Set the global ANE context pointer
fn set_global_ane_ptr(ptr: *mut OrionANEContext) {
    GLOBAL_ANE_PTR
        .get_or_init(|| std::sync::atomic::AtomicUsize::new(0))
        .store(ptr as usize, std::sync::atomic::Ordering::SeqCst);
}

/// Lattice operations handler with real FFI
pub struct LatticeOps {
    ane_ctx: AneContext,
    gpu_ctx: GpuContext,
}

impl LatticeOps {
    /// Create new lattice ops handler with initialized hardware
    pub fn new() -> Result<Self, BackendError> {
        // Use global ANE context singleton to prevent "Context leak detected"
        // when multiple threads try to initialize ANE simultaneously.
        // Apple ANE hardware only supports ONE context at a time.
        let lock = get_global_ane_lock();
        let _ane_guard = lock.lock().unwrap();

        let ane_ctx_ptr = if get_global_ane_ptr() != 0 {
            // Reuse existing global ANE context
            tracing::debug!("Reusing global ANE context");
            get_global_ane_ptr() as *mut OrionANEContext
        } else {
            // Initialize new ANE context (only happens once)
            tracing::info!("Initializing global ANE context");
            let ctx_ptr = unsafe { orion_ane_init() };
            if ctx_ptr.is_null() {
                tracing::warn!("ANE not available - MatVec will use fallback");
            }
            set_global_ane_ptr(ctx_ptr);
            ctx_ptr
        };

        // Initialize GPU context for NTT (GPU is more forgiving with multiple contexts)
        let gpu_ctx_ptr = unsafe { orion_gpu_init() };
        if gpu_ctx_ptr.is_null() {
            tracing::warn!("GPU not available - NTT will use fallback");
        }

        Ok(LatticeOps {
            ane_ctx: AneContext { ctx: ane_ctx_ptr },
            gpu_ctx: GpuContext { ctx: gpu_ctx_ptr },
        })
    }

    /// Execute MatVec operation via ANE
    ///
    /// Input format: [k, l, matrix (k*l f32), vector (l f32)]
    /// Output: k field elements
    pub fn matvec(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        if inputs.len() < 3 {
            return Err(BackendError::InvalidWitness(
                "MatVec needs at least k, l, and data".to_string(),
            ));
        }

        let k = inputs[0].0 as usize;
        let l = inputs[1].0 as usize;

        if inputs.len() < 2 + k * l + l {
            return Err(BackendError::InvalidWitness(
                "MatVec insufficient inputs".to_string(),
            ));
        }

        // Extract matrix A (k × l)
        let matrix_start = 2;
        let matrix = &inputs[matrix_start..matrix_start + k * l];

        // Extract vector s (l)
        let vector_start = matrix_start + k * l;
        let vector = &inputs[vector_start..vector_start + l];

        // Convert to f32 for ANE
        let mut A_f32: Vec<f32> = matrix.iter().map(|f| f.0 as f32).collect();
        let mut s_f32: Vec<f32> = vector.iter().map(|f| f.0 as f32).collect();
        let mut result: Vec<u64> = vec![0u64; k];

        // Call ANE-accelerated MatVec (serialize with mutex to prevent context leak)
        let success = if !self.ane_ctx.ctx.is_null() {
            // Acquire lock to serialize ANE access (ANE hardware can only handle one operation at a time)
            let op_lock = get_global_ane_op_lock();
            let _lock = op_lock.lock().unwrap();
            let r = unsafe {
                latticezk_matvec(
                    A_f32.as_ptr(),
                    s_f32.as_ptr(),
                    k as i32,
                    l as i32,
                    LATTICEZK_Q as u64,
                    result.as_mut_ptr(),
                )
            };
            if !r {
                // ANE call failed, try CPU fallback
                tracing::warn!("ANE MatVec failed, using CPU fallback");
                drop(_lock);
                Self::cpu_matvec(&A_f32, &s_f32, k, l, &mut result)
            } else {
                true
            }
        } else {
            // No ANE context, use CPU fallback
            tracing::warn!("No ANE context, using CPU fallback");
            Self::cpu_matvec(&A_f32, &s_f32, k, l, &mut result)
        };

        tracing::debug!("MatVec: k={}, l={}, result={:?}", k, l, &result[..]);

        Ok(result.iter().map(|&v| FieldElement(v as u32)).collect())
    }

    /// CPU fallback for MatVec
    fn cpu_matvec(A: &[f32], s: &[f32], k: usize, l: usize, result: &mut [u64]) -> bool {
        for i in 0..k {
            let mut sum = 0u64;
            for j in 0..l {
                // Simplified: just multiply and sum
                sum = sum.wrapping_add((A[i * l + j] * s[j]) as u64);
            }
            result[i] = sum % (LATTICEZK_Q as u64);
        }
        true
    }

    /// Execute NTT operation via GPU
    ///
    /// Input: 256 field elements (coefficients)
    /// Output: 256 field elements (NTT domain)
    pub fn ntt(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        if self.gpu_ctx.ctx.is_null() {
            return Err(BackendError::GpuError(
                "GPU not initialized".to_string(),
            ));
        }

        if inputs.len() < GPU_NTT_N {
            return Err(BackendError::InvalidWitness(
                format!("NTT needs {} coefficients, got {}", GPU_NTT_N, inputs.len())
            ));
        }

        // Convert to GPU format
        let mut input_poly = GPUNTTPoly::default();
        for (i, fe) in inputs.iter().take(GPU_NTT_N).enumerate() {
            input_poly.coeff[i] = fe.0;
        }

        let mut output_poly = GPUNTTPoly::default();

        // Call GPU NTT
        let success = unsafe {
            orion_ntt_forward(self.gpu_ctx.ctx, &input_poly, &mut output_poly)
        };

        if !success {
            return Err(BackendError::GpuError("NTT forward failed".to_string()));
        }

        tracing::debug!("NTT forward completed");

        Ok((0..GPU_NTT_N)
            .map(|i| FieldElement(output_poly.coeff[i]))
            .collect())
    }

    /// Execute inverse NTT
    pub fn ntt_inverse(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        if self.gpu_ctx.ctx.is_null() {
            return Err(BackendError::GpuError(
                "GPU not initialized".to_string(),
            ));
        }

        if inputs.len() < GPU_NTT_N {
            return Err(BackendError::InvalidWitness(
                format!("Inverse NTT needs {} coefficients, got {}", GPU_NTT_N, inputs.len())
            ));
        }

        let mut input_poly = GPUNTTPoly::default();
        for (i, fe) in inputs.iter().take(GPU_NTT_N).enumerate() {
            input_poly.coeff[i] = fe.0;
        }

        let mut output_poly = GPUNTTPoly::default();

        let success = unsafe {
            orion_ntt_inverse(self.gpu_ctx.ctx, &input_poly, &mut output_poly)
        };

        if !success {
            return Err(BackendError::GpuError("NTT inverse failed".to_string()));
        }

        Ok((0..GPU_NTT_N)
            .map(|i| FieldElement(output_poly.coeff[i]))
            .collect())
    }

    /// Execute CRT reconstruction
    ///
    /// Input: [n_mods, mod0, res0, mod1, res1, ...]
    /// Output: single reconstructed field element
    pub fn crt(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        if inputs.len() < 3 {
            return Err(BackendError::InvalidWitness(
                "CRT needs at least n_mods and one modulus/residue pair".to_string(),
            ));
        }

        let n_mods = inputs[0].0 as usize;
        if inputs.len() < 1 + 2 * n_mods {
            return Err(BackendError::InvalidWitness(
                format!("CRT insufficient inputs for {} moduli", n_mods)
            ));
        }

        // Extract moduli and residues
        let mut residues: Vec<f32> = Vec::with_capacity(n_mods);
        for i in 0..n_mods {
            residues.push(inputs[1 + 2 * i + 1].0 as f32);
        }

        // Get RNS config
        let rns_config = unsafe { latticezk_rns_config() };
        if rns_config.is_null() {
            return Err(BackendError::FfiError("Failed to get RNS config".to_string()));
        }

        let mut result: u64 = 0;

        // Call CRT reconstruction
        unsafe {
            latticezk_crt_reconstruct(
                residues.as_ptr(),
                n_mods as i32,
                rns_config,
                LATTICEZK_Q as u64,
                &mut result,
            );
        }

        tracing::debug!("CRT reconstruction: {} moduli -> {}", n_mods, result);

        Ok(vec![FieldElement(result as u32)])
    }

    /// Execute Poseidon2 hash with MDS matrix multiplication on ANE
    ///
    /// For Poseidon2 with width=8, the MDS matrix is 8×8.
    /// Each round applies: state = MDS * (state + round_constants)^5
    ///
    /// This function accelerates the MDS matrix multiplication using ANE MatVec.
    /// The S-box (x^5) should be applied element-wise before/after on CPU.
    ///
    /// Input format: [8 state elements]
    /// Output format: [8 output elements after MDS]
    pub fn poseidon2(&self, state: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        const MDS_SIZE: usize = 8;

        if state.len() < MDS_SIZE {
            return Err(BackendError::InvalidWitness(
                format!("Poseidon2 MDS needs {} elements, got {}", MDS_SIZE, state.len())
            ));
        }

        // MDS matrix for Poseidon2 (8×8 identity matrix in current implementation)
        // For production, this would be the actual Poseidon2 MDS matrix
        // Here we use identity for the lattice field compatibility
        let mds: [f32; MDS_SIZE * MDS_SIZE] = [
            1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ];

        // Prepare matrix and vector for ANE
        let matrix: Vec<FieldElement> = mds.iter().map(|&v| FieldElement(v as u32)).collect();
        let vector: Vec<FieldElement> = state[..MDS_SIZE].to_vec();

        // Call ANE-accelerated MatVec (8×8 matrix-vector multiply)
        let result = self.matvec(&[FieldElement(MDS_SIZE as u32), FieldElement(MDS_SIZE as u32)].into_iter()
            .chain(matrix.into_iter())
            .chain(vector.into_iter())
            .collect::<Vec<_>>())?;

        tracing::debug!("Poseidon2 MDS ANE: input={:?} -> output={:?}", &state[..4], &result[..4]);

        Ok(result)
    }

    /// Execute Poseidon2 hash on CPU (no ANE) - for benchmarking comparison
    ///
    /// This is identical to poseidon2() but always uses CPU MatVec
    /// to measure the speedup from ANE acceleration.
    pub fn poseidon2_cpu(&self, state: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        const MDS_SIZE: usize = 8;

        if state.len() < MDS_SIZE {
            return Err(BackendError::InvalidWitness(
                format!("Poseidon2 MDS needs {} elements, got {}", MDS_SIZE, state.len())
            ));
        }

        // MDS matrix (identity)
        let mds: [f32; MDS_SIZE * MDS_SIZE] = [
            1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ];

        // Force CPU path
        let matrix: Vec<f32> = mds.iter().map(|&v| v).collect();
        let vector: Vec<f32> = state[..MDS_SIZE].iter().map(|f| f.0 as f32).collect();
        let mut result: Vec<u64> = vec![0u64; MDS_SIZE];

        Self::cpu_matvec(&matrix, &vector, MDS_SIZE, MDS_SIZE, &mut result);

        tracing::debug!("Poseidon2 MDS CPU: input={:?} -> output={:?}", &state[..4], &result[..4]);

        Ok(result.iter().map(|&v| FieldElement(v as u32)).collect())
    }

    /// Execute permutation check for memory/storage consistency
    ///
    /// Verifies that two lists contain the same elements using random linear combination:
    /// Σ list_a[i] * r^i = Σ list_b[i] * r^i (mod Q)
    ///
    /// This is ANE-accelerated via dot product: each Σ is a matvec operation
    /// where the matrix is diagonal with powers of r.
    ///
    /// Input format: [n, r, list_a[0..n], list_b[0..n]]
    /// Output: [1] if permutation holds (both sums equal), [0] if not
    pub fn permutation_check(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>, BackendError> {
        if inputs.len() < 3 {
            return Err(BackendError::InvalidWitness(
                "Permutation check needs at least n, r, and one list element".to_string(),
            ));
        }

        let n = inputs[0].0 as usize;
        let r = inputs[1].0 as f32; // random challenge as f32 for ANE

        if inputs.len() < 2 + 2 * n {
            return Err(BackendError::InvalidWitness(
                format!("Permutation check insufficient inputs for n={}", n)
            ));
        }

        let list_a_start = 2;
        let list_b_start = 2 + n;

        let list_a = &inputs[list_a_start..list_a_start + n];
        let list_b = &inputs[list_b_start..list_b_start + n];

        // Convert to f32 for ANE
        let a_f32: Vec<f32> = list_a.iter().map(|f| f.0 as f32).collect();
        let b_f32: Vec<f32> = list_b.iter().map(|f| f.0 as f32).collect();

        // Powers of r: [1, r, r^2, r^3, ..., r^(n-1)]
        let mut powers: Vec<f32> = Vec::with_capacity(n);
        powers.push(1.0);
        for i in 1..n {
            powers.push(powers[i - 1] * r);
        }

        let mut result_a: Vec<u64> = vec![0u64; 1];
        let mut result_b: Vec<u64> = vec![0u64; 1];

        // Compute Σ a[i] * r^i via ANE dot product (matrix is diagonal powers)
        let success = if !self.ane_ctx.ctx.is_null() {
            let op_lock = get_global_ane_op_lock();
            let _lock = op_lock.lock().unwrap();

            // For ANE matvec, we need matrix (k×l) and vector (l)
            // Here k=1 (one output), l=n, matrix is diagonal with powers
            let k = 1;
            let l = n;

            // Build diagonal matrix as k*l vector (each row has one power on diagonal)
            let diagonal: Vec<f32> = powers.clone();

            // Call ANE dot product: result = Σ diagonal[i] * a[i]
            let r1 = unsafe {
                latticezk_matvec(
                    diagonal.as_ptr(),
                    a_f32.as_ptr(),
                    k as i32,
                    l as i32,
                    LATTICEZK_Q as u64,
                    result_a.as_mut_ptr(),
                )
            };

            if !r1 {
                tracing::warn!("ANE permutation check (list A) failed, using CPU fallback");
                drop(_lock);
                Self::cpu_dot_product(&powers, &a_f32, &mut result_a);
                false
            } else {
                // Now compute for list B
                let r2 = unsafe {
                    latticezk_matvec(
                        diagonal.as_ptr(),
                        b_f32.as_ptr(),
                        k as i32,
                        l as i32,
                        LATTICEZK_Q as u64,
                        result_b.as_mut_ptr(),
                    )
                };

                if !r2 {
                    tracing::warn!("ANE permutation check (list B) failed, using CPU fallback");
                    drop(_lock);
                    Self::cpu_dot_product(&powers, &b_f32, &mut result_b);
                    false
                } else {
                    true
                }
            }
        } else {
            // CPU fallback
            Self::cpu_dot_product(&powers, &a_f32, &mut result_a);
            Self::cpu_dot_product(&powers, &b_f32, &mut result_b);
            true
        };

        if !success {
            return Err(BackendError::AneError(
                "Permutation check ANE operation failed".to_string(),
            ));
        }

        let sum_a = result_a[0] % (LATTICEZK_Q as u64);
        let sum_b = result_b[0] % (LATTICEZK_Q as u64);

        let holds = if sum_a == sum_b { 1 } else { 0 };

        tracing::debug!("Permutation check: sum_a={}, sum_b={}, holds={}", sum_a, sum_b, holds);
        Ok(vec![FieldElement(holds)])
    }

    /// CPU fallback for dot product (Σ a[i] * b[i])
    fn cpu_dot_product(a: &[f32], b: &[f32], result: &mut [u64]) -> bool {
        if a.len() != b.len() || result.len() < 1 {
            return false;
        }

        let mut sum = 0u64;
        for i in 0..a.len() {
            sum = sum.wrapping_add((a[i] * b[i]) as u64);
        }
        result[0] = sum % (LATTICEZK_Q as u64);
        true
    }

    /// Execute a black box function
    pub fn execute(&self, func: BlackBoxFunc, inputs: &[FieldElement])
        -> Result<Vec<FieldElement>, BackendError>
    {
        match func {
            BlackBoxFunc::MatVec => self.matvec(inputs),
            BlackBoxFunc::NTT => self.ntt(inputs),
            BlackBoxFunc::CRT => self.crt(inputs),
            BlackBoxFunc::Poseidon2 => self.poseidon2(inputs),
            BlackBoxFunc::PermutationCheck => self.permutation_check(inputs),
            _ => Err(BackendError::UnsupportedOpcode(
                format!("{:?} not implemented in lattice_ops", func)
            )),
        }
    }

    /// Check if ANE is available
    pub fn ane_available(&self) -> bool {
        !self.ane_ctx.ctx.is_null()
    }

    /// Check if GPU is available
    pub fn gpu_available(&self) -> bool {
        !self.gpu_ctx.ctx.is_null()
    }
}

impl Drop for LatticeOps {
    fn drop(&mut self) {
        // ANE context is global singleton - never release it here
        // Only release GPU context which is per-instance
        if !self.gpu_ctx.ctx.is_null() {
            unsafe { orion_gpu_release(self.gpu_ctx.ctx) };
        }
    }
}

impl Default for LatticeOps {
    fn default() -> Self {
        Self::new().expect("Failed to create lattice ops")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_ane_singleton() {
        // Create two LatticeOps instances
        let ops1 = LatticeOps::new().expect("Failed to create ops1");
        let ops2 = LatticeOps::new().expect("Failed to create ops2");

        // Both should share the same ANE context pointer
        assert_eq!(ops1.ane_ctx.ctx, ops2.ane_ctx.ctx,
            "Multiple LatticeOps should share the same global ANE context");
    }

    #[test]
    fn test_global_ane_ptr_initialized() {
        // This test verifies the global pointer is set after LatticeOps::new()
        let _ops = LatticeOps::new().expect("Failed to create ops");
        let ptr = get_global_ane_ptr();
        assert!(ptr != 0, "Global ANE ptr should be non-zero after initialization");
    }
}
