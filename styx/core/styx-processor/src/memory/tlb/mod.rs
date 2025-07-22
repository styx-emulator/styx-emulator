// SPDX-License-Identifier: BSD-2-Clause

mod dummy;
pub use dummy::DummyTlb;

mod closure;
pub use closure::ClosureTlb;

use styx_errors::UnknownError;
use thiserror::Error;

use crate::memory::mmu::MemoryType;
use crate::memory::physical::MemoryBackend;
use crate::memory::MemoryOperation;
use crate::{cpu::CpuBackend, event_controller::ExceptionNumber};

#[derive(Error, Debug)]
pub enum TlbTranslateError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    /// Indicates a TLB error with an associated exception to synchronously execute.
    ///
    /// The CPU will through an interrupt hook with this exception number.
    #[error("TLB exception irqn: {0:?}")]
    Exception(ExceptionNumber),
}

/// Processor components for a TLB translate.
///
/// The MMU will construct this before calling [`TlbImpl::translate_va()`].
///
/// Construct with [`Self::new()`].
pub struct TlbProcessor<'a> {
    pub physical_memory: &'a mut MemoryBackend,
    pub cpu: &'a mut dyn CpuBackend,
}

impl<'a> TlbProcessor<'a> {
    pub fn new(physical_memory: &'a mut MemoryBackend, cpu: &'a mut dyn CpuBackend) -> Self {
        Self {
            physical_memory,
            cpu,
        }
    }
}

/// Returns the translated physical address or error.
pub type TlbTranslateResult = Result<u64, TlbTranslateError>;

/// The common interface for TLB implementations.  It defines methods for
/// performing address translations, reading/writing the TLB, updating TLB
/// state, and invalidating TLB entries.
pub trait TlbImpl: Send {
    /// Do any setup
    fn init(&mut self, _cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Enable translation for data addresses
    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Disable translation for data addresses
    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Enable translation for code addresses
    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Disable translation for code addresses
    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Translate a virtual address to a physical address.
    ///
    /// This is called from [`Mmu::virt_code()`](crate::memory::Mmu::virt_code()) and related
    /// virtual memory access functions. It is also used for all loads, stores, and fetches inside
    /// the pcode cpu backend.
    ///
    /// Implementors can return [`TlbTranslateError::Exception`] to instruct the CPU to trigger an
    /// interrupt hook with a designed exception number.
    fn translate_va(
        &mut self,
        virt_addr: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        processor: &mut TlbProcessor,
    ) -> TlbTranslateResult;

    /// Write to the TLB, it is up to the implementation to interpret the idx, data, and flags arguments
    fn tlb_write(&mut self, idx: usize, data: u64, flags: u32) -> Result<(), TlbTranslateError>;

    /// Read from the TLB, it is up to the implementation to interpret the idx and flags arguments
    fn tlb_read(&self, idx: usize, flags: u32) -> Result<u64, TlbTranslateError>;

    /// Invalidate all tlb entries, implementation specific flags are passed to control behaviour
    fn invalidate_all(&mut self, flags: u32) -> Result<(), UnknownError>;

    /// Invalidate a single tlb entry, based on an index value.
    ///
    /// The implementation decides how to interpret the idx value.
    fn invalidate(&mut self, idx: usize) -> Result<(), UnknownError>;
}
