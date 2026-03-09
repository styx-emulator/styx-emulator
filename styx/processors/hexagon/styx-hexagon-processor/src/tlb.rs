// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::bitfield;
use styx_core::{
    errors::UnknownError,
    memory::{
        MemoryOperation, MemoryType, TlbImpl, TlbProcessor, TlbTranslateError, TlbTranslateResult,
    },
};

#[bitfield(u64, debug)]
struct Pte {
    // Physical page descriptor
    #[bits(0..=23, rw)]
    ppd: u24,
    #[bits(24..=27, rw)]
    c: u4,
    #[bit(28, rw)]
    u: bool,
    #[bit(29, rw)]
    r: bool,
    #[bit(30, rw)]
    w: bool,
    #[bit(31, rw)]
    x: bool,
    #[bits(32..=51, rw)]
    vpn: u20,
    #[bits(52..=58, rw)]
    asid: u7,
    #[bit(59, rw)]
    atr0: bool,
    #[bit(60, rw)]
    atr1: bool,
    #[bit(61, rw)]
    pa35: bool,
    #[bit(62, rw)]
    g: bool,
    #[bit(63, rw)]
    v: bool,
}

pub struct HexagonTlb;

impl HexagonTlb {
    pub fn new() -> Self {
        Self {}
    }
}

impl TlbImpl for HexagonTlb {
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

    fn translate_va(
        &mut self,
        virt_addr: u64,
        _access_type: MemoryOperation,
        _memory_type: MemoryType,
        _processor: &mut TlbProcessor,
    ) -> TlbTranslateResult {
        // Translation is not implemented for now
        Ok(virt_addr)
    }

    fn tlb_write(&mut self, _idx: usize, _data: u64, _flags: u32) -> Result<(), TlbTranslateError> {
        Ok(())
    }

    fn tlb_read(&self, _idx: usize, _flags: u32) -> Result<u64, TlbTranslateError> {
        todo!()
    }

    fn invalidate_all(&mut self, _flags: u32) -> Result<(), UnknownError> {
        todo!()
    }

    fn invalidate(&mut self, _idx: usize) -> Result<(), UnknownError> {
        todo!()
    }
}
