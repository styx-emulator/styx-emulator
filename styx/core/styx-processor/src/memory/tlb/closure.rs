// SPDX-License-Identifier: BSD-2-Clause

use styx_errors::UnknownError;

use crate::memory::{
    mmu::MemoryType,
    tlb::{TlbProcessor, TlbTranslateResult},
    MemoryOperation, TlbImpl, TlbTranslateError,
};

/// TLB implementation that takes a function pointer to calculate virtual addressing.
///
/// This is a useful [TlbImpl] for TLB's to test virtual address, i.e. by just passing a function to
/// perform a simple translation. Proper processor implementations should not use this and instead
/// implement [TlbImpl].
pub struct FnTlb {
    function: TranslateFn,
}

pub type TranslateFn =
    fn(u64, MemoryOperation, MemoryType, &mut TlbProcessor) -> TlbTranslateResult;

impl FnTlb {
    pub fn new(function: TranslateFn) -> Self {
        Self { function }
    }
}

impl TlbImpl for FnTlb {
    fn translate_va(
        &mut self,
        virt_addr: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        processor: &mut TlbProcessor,
    ) -> TlbTranslateResult {
        (self.function)(virt_addr, access_type, memory_type, processor)
    }

    fn invalidate_all(&mut self, _flags: u32) -> Result<(), UnknownError> {
        Ok(())
    }

    fn invalidate(&mut self, _idx: usize) -> Result<(), UnknownError> {
        Ok(())
    }

    fn tlb_write(&mut self, _idx: usize, _data: u64, _flags: u32) -> Result<(), TlbTranslateError> {
        Ok(())
    }

    fn tlb_read(&self, _idx: usize, _flags: u32) -> Result<u64, TlbTranslateError> {
        Ok(0)
    }

    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }
}
