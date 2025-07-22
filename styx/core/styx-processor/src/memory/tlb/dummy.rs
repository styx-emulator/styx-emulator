// SPDX-License-Identifier: BSD-2-Clause

use styx_errors::UnknownError;

use crate::memory::{
    mmu::MemoryType,
    tlb::{TlbProcessor, TlbTranslateResult},
    MemoryOperation, TlbImpl, TlbTranslateError,
};

/// TLB implementation that has no address translation.
#[derive(Debug, Default)]
pub struct DummyTlb;
impl TlbImpl for DummyTlb {
    fn translate_va(
        &mut self,
        virt_addr: u64,
        _access_type: MemoryOperation,
        _memory_type: MemoryType,
        _processor: &mut TlbProcessor,
    ) -> TlbTranslateResult {
        Ok(virt_addr)
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
