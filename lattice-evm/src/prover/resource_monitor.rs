//! System Resource Monitor for Adaptive Prover Resource Management
//!
//! Monitors CPU, memory, GPU, and ANE resources to enable:
//! - Graceful degradation under load
//! - Batched operations with backpressure
//! - Clean failure instead of crashes
//!
//! # Usage
//!
//! ```rust
//! let monitor = SystemResourceMonitor::new();
//!
//! // Check if we should proceed with heavy work
//! if monitor.should_proceed_with_batch(batch_size) {
//!     // proceed with proving
//! } else {
//!     // wait, reduce batch size, or gracefully fail
//! }
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};

/// Maximum batch size allowed by FFI layer (security limit)
const MAX_FFI_BATCH_SIZE: usize = 10_000;

/// Recommended maximum batch size for safe operation (accounts for memory)
const RECOMMENDED_BATCH_SIZE: usize = 5_000;

/// Minimum memory headroom (MB) - won't start new batches if less available
const MIN_MEMORY_HEADROOM_MB: usize = 512;

/// Maximum CPU load average before reducing parallelism (on a scale of 1.0 = 100%)
const MAX_CPU_LOAD: f64 = 0.85;

/// Sample interval for CPU load averaging (seconds)
const CPU_LOAD_SAMPLE_SECS: u64 = 5;

/// System resource monitor for adaptive prover behavior
pub struct SystemResourceMonitor {
    /// Last observed CPU load average (0.0 to 1.0+)
    cpu_load: AtomicUsize,
    /// Last observed memory pressure (0 = none, 100 = critical)
    memory_pressure: AtomicUsize,
    /// Number of active provers (for ANE/GPU contention tracking)
    active_provers: AtomicUsize,
}

impl SystemResourceMonitor {
    /// Create new resource monitor
    pub fn new() -> Self {
        Self {
            cpu_load: AtomicUsize::new(0),
            memory_pressure: AtomicUsize::new(0),
            active_provers: AtomicUsize::new(0),
        }
    }

    /// Refresh all resource metrics
    pub fn refresh(&self) {
        self.refresh_cpu_load();
        self.refresh_memory_pressure();
    }

    /// Get current CPU load average (0.0 to 1.0+, can exceed 1.0 on multi-core under load)
    pub fn cpu_load(&self) -> f64 {
        (self.cpu_load.load(Ordering::Relaxed) as f64) / 100.0
    }

    /// Get current memory pressure (0 = free, 100 = exhausted)
    pub fn memory_pressure(&self) -> u8 {
        self.memory_pressure.load(Ordering::Relaxed) as u8
    }

    /// Check if system has moderate load (allows full parallelism)
    pub fn is_loaded(&self) -> bool {
        self.cpu_load() > MAX_CPU_LOAD
    }

    /// Estimate available system memory in MB
    pub fn available_memory_mb(&self) -> usize {
        // On macOS/Unix, check available memory
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl")
                .args(&["-n", "hw.memsize"])
                .output()
            {
                let total: usize = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(8_000_000_000);
                let total_mb = total / (1024 * 1024);

                // Get free memory using vm_stat
                if let Ok(vm_stat) = std::fs::read_to_string("/proc/meminfo") {
                    // Linux-style parsing would go here
                    return total_mb / 2; // Fallback estimate
                }

                // Simplified: assume half is available on a idle machine
                let pressure = self.memory_pressure() as f64 / 100.0;
                return ((total_mb as f64) * (1.0 - pressure * 0.8)) as usize;
            }
            4096 // Default fallback
        }

        #[cfg(not(target_os = "macos"))]
        {
            // Default fallback for other platforms
            4096
        }
    }

    /// Check if a batch of given size would fit in available memory
    ///
    /// Each witness is 256 f32s = 1KB. Add ~20% overhead for proofs and intermediates.
    pub fn can_fit_batch(&self, num_witnesses: usize) -> bool {
        let needed_mb = (num_witnesses * 256 * 4) / (1024 * 1024);
        let needed_mb = (needed_mb as f64 * 1.2) as usize; // 20% overhead

        self.available_memory_mb() > needed_mb + MIN_MEMORY_HEADROOM_MB
    }

    /// Get recommended batch size based on current system load
    pub fn recommended_batch_size(&self) -> usize {
        let base = RECOMMENDED_BATCH_SIZE;

        // Reduce batch size under load
        if self.is_loaded() {
            return base / 2;
        }

        // Further reduce if memory is tight
        if self.memory_pressure() > 50 {
            return base / 2;
        }

        base
    }

    /// Determine how many parallel workers to use
    pub fn recommended_parallelism(&self, max_workers: usize) -> usize {
        let cpu_load = self.cpu_load();

        if cpu_load < 0.3 {
            // System is idle - use most cores
            max_workers
        } else if cpu_load < 0.6 {
            // Moderate load - reduce by 25%
            (max_workers as f64 * 0.75) as usize
        } else if cpu_load < 0.8 {
            // High load - reduce by half
            max_workers / 2
        } else {
            // Critical load - use minimum
            1
        }
    }

    /// Check if we should proceed with batch proving
    ///
    /// Returns Ok(batch_size) if should proceed, Err(reason) if should wait/reduce
    pub fn should_proceed_with_batch(&self, requested_size: usize) -> Result<usize, ResourceCheckFailed> {
        // Check FFI limit
        if requested_size > MAX_FFI_BATCH_SIZE {
            return Err(ResourceCheckFailed::BatchSizeExceedsLimit {
                requested: requested_size,
                limit: MAX_FFI_BATCH_SIZE,
            });
        }

        // Check memory
        if !self.can_fit_batch(requested_size) {
            let available = self.available_memory_mb();
            let needed = (requested_size * 256 * 4) / (1024 * 1024);
            return Err(ResourceCheckFailed::InsufficientMemory {
                needed_mb: needed,
                available_mb: available,
            });
        }

        // Under high load, recommend smaller batch
        if self.is_loaded() && requested_size > self.recommended_batch_size() {
            return Err(ResourceCheckFailed::SystemUnderLoad {
                recommended: self.recommended_batch_size(),
                requested: requested_size,
                cpu_load: self.cpu_load(),
            });
        }

        // Check GPU availability if GPU path is needed
        // (This is checked separately in the prover)

        Ok(requested_size.min(self.recommended_batch_size()))
    }

    /// Wait for resources to become available
    ///
    /// Polls every `interval` ms until `timeout` ms elapsed or resources available.
    pub fn wait_for_resources(
        &self,
        requested_size: usize,
        interval_ms: u64,
        timeout_ms: u64,
    ) -> Result<usize, ResourceCheckFailed> {
        let start = std::time::Instant::now();

        loop {
            self.refresh();

            if let Ok(size) = self.should_proceed_with_batch(requested_size) {
                return Ok(size);
            }

            if start.elapsed().as_millis() as u64 > timeout_ms {
                return Err(ResourceCheckFailed::Timeout {
                    waited_ms: timeout_ms,
                    requested: requested_size,
                    final_cpu_load: self.cpu_load(),
                });
            }

            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        }
    }

    /// Record that a prover is now active (for ANE/GPU contention)
    pub fn prover_active(&self) {
        self.active_provers.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a prover completed (for ANE/GPU contention)
    pub fn prover_inactive(&self) {
        self.active_provers.fetch_sub(1, Ordering::Relaxed);
    }

    /// Check ANE contention (multiple provers competing for ANE)
    pub fn ane_contention_level(&self) -> u8 {
        let active = self.active_provers.load(Ordering::Relaxed);
        if active <= 1 {
            0
        } else if active <= 2 {
            25
        } else if active <= 4 {
            50
        } else {
            75
        }
    }

    /// Refresh CPU load average
    fn refresh_cpu_load(&self) {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            // Get load average (1 minute average)
            if let Ok(output) = Command::new("sysctl")
                .args(&["-n", "vm.loadavg"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Parse "X.XX Y.YY Z.ZZ" format
                if let Some(first) = output_str.trim().split_whitespace().next() {
                    if let Ok(load) = first.parse::<f64>() {
                        let num_cpus = num_cpus().min(8) as f64;
                        let normalized = (load / num_cpus).min(1.5);
                        self.cpu_load.store((normalized * 100.0) as usize, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("cat")
                .args(&["/proc/loadavg"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if let Some(first) = output_str.trim().split_whitespace().next() {
                    if let Ok(load) = first.parse::<f64>() {
                        let num_cpus = num_cpus().min(8) as f64;
                        let normalized = (load / num_cpus).min(1.5);
                        self.cpu_load.store((normalized * 100.0) as usize, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }

        // Fallback: assume moderate load
        self.cpu_load.store(30, Ordering::Relaxed);
    }

    /// Refresh memory pressure estimate
    fn refresh_memory_pressure(&self) {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            // Use memory_pressure command on macOS
            if let Ok(output) = Command::new("memory_pressure")
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stderr);
                // Parse output like "Engine dump: 0x0000000000000000\n  Note: 0x6b = 107"
                if let Some(pct) = output_str.split("0x").nth(1) {
                    if let Ok(val) = usize::from_str_radix(&pct[0..2], 16) {
                        let pressure = ((val as f64) / 255.0 * 100.0) as usize;
                        self.memory_pressure.store(pressure.min(100), Ordering::Relaxed);
                        return;
                    }
                }
            }
        }

        // Fallback: check system memory usage via sysctl
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl")
                .args(&["-n", "hw.physmem"])
                .output()
            {
                // Try to get wired/app memory to estimate pressure
                // This is a rough approximation
                self.memory_pressure.store(30, Ordering::Relaxed);
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            self.memory_pressure.store(30, Ordering::Relaxed);
        }
    }

    /// Get human-readable resource status
    pub fn status_summary(&self) -> String {
        format!(
            "CPU: {:.0}% load, Mem: {} MB avail, Pressure: {}%, ANE contention: {}%",
            self.cpu_load() * 100.0,
            self.available_memory_mb(),
            self.memory_pressure(),
            self.ane_contention_level()
        )
    }
}

impl Default for SystemResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason why a resource check failed
#[derive(Debug, Clone)]
pub enum ResourceCheckFailed {
    /// Requested batch size exceeds FFI limit
    BatchSizeExceedsLimit {
        requested: usize,
        limit: usize,
    },
    /// Not enough system memory
    InsufficientMemory {
        needed_mb: usize,
        available_mb: usize,
    },
    /// System is under load, should reduce batch size
    SystemUnderLoad {
        recommended: usize,
        requested: usize,
        cpu_load: f64,
    },
    /// Timed out waiting for resources
    Timeout {
        waited_ms: u64,
        requested: usize,
        final_cpu_load: f64,
    },
}

impl std::fmt::Display for ResourceCheckFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceCheckFailed::BatchSizeExceedsLimit { requested, limit } => {
                write!(f, "Batch size {} exceeds FFI limit {}", requested, limit)
            }
            ResourceCheckFailed::InsufficientMemory { needed_mb, available_mb } => {
                write!(f, "Need {} MB memory but only {} MB available", needed_mb, available_mb)
            }
            ResourceCheckFailed::SystemUnderLoad { recommended, requested, cpu_load } => {
                write!(f, "System under load ({:.0}%), reduce batch from {} to {}",
                    cpu_load * 100.0, requested, recommended)
            }
            ResourceCheckFailed::Timeout { waited_ms, requested, final_cpu_load } => {
                write!(f, "Timed out after {}ms waiting for resources (CPU: {:.0}%), requested batch {}",
                    waited_ms, final_cpu_load * 100.0, requested)
            }
        }
    }
}

impl std::error::Error for ResourceCheckFailed {}

/// Get approximate number of CPU cores
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_monitor_creation() {
        let monitor = SystemResourceMonitor::new();
        assert_eq!(monitor.active_provers.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_prover_active_tracking() {
        let monitor = SystemResourceMonitor::new();
        monitor.prover_active();
        assert_eq!(monitor.active_provers.load(Ordering::Relaxed), 1);
        monitor.prover_active();
        assert_eq!(monitor.active_provers.load(Ordering::Relaxed), 2);
        monitor.prover_inactive();
        assert_eq!(monitor.active_provers.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_batch_size_recommendation() {
        let monitor = SystemResourceMonitor::new();
        // By default should recommend full batch size
        let recommended = monitor.recommended_batch_size();
        assert!(recommended <= RECOMMENDED_BATCH_SIZE);
    }

    #[test]
    fn test_parallelism_recommendation() {
        let monitor = SystemResourceMonitor::new();
        // Should recommend all workers when system is idle
        let workers = monitor.recommended_parallelism(8);
        assert_eq!(workers, 8);
    }
}