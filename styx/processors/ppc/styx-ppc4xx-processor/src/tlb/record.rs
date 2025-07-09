// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[derive(Debug, Default, Clone, Copy)]
pub struct TlbRecord {
    /// 8 bit processor id
    pub pid: u8,
    /// the real bits for the tag portion of the tlb record
    pub raw_hi: u32,
    /// the real bits for the data portion of the tlb record
    pub raw_lo: u32,

    /// is this translation valid or not
    pub valid: bool,
    /// virtual base address
    pub virtual_page_start: u64,
    /// virtual end address, exclusive
    pub virtual_page_end: u64,

    /// physical base address
    pub physical_page_base: u64,
    pub physical_page_mask: u64,
    pub exec_enabled: bool,
    pub write_enabled: bool,
}

const KB: u64 = 1024;
const MB: u64 = 1024 * 1024;

const EPN_MASK: u32 = 0b11_1111_1111_1111_1111_1111;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 0b111;
const VALID_SHIFT: u32 = 3;
const VALID_MASK: u32 = 0b1;

const RPN_MASK: u32 = 0b11_1111_1111_1111_1111_1111;
const EX_SHIFT: u32 = 22;
const WR_SHIFT: u32 = 1;

impl TlbRecord {
    /// converts the 3 bit size field into a u64 size and a u64 mask
    fn size_bits_to_u64_and_mask(&self, size: u8) -> (u64, u64) {
        match size & 0b111 {
            0b000 => (KB, 0b11_1111_1111),
            0b001 => (4 * KB, 0b1111_1111_1111),
            0b010 => (16 * KB, 0b11_1111_1111_1111),
            0b011 => (64 * KB, 0b1111_1111_1111_1111),
            0b100 => (256 * KB, 0b11_1111_1111_1111_1111),
            0b101 => (MB, 0b1111_1111_1111_1111_1111),
            0b110 => (4 * MB, 0b11_1111_1111_1111_1111_1111),
            0b111 => (16 * MB, 0b1111_1111_1111_1111_1111_1111),
            _ => unreachable!(),
        }
    }

    /// Extracts the relevant fields from the tag portion of the TLB record.
    pub fn write_high(&mut self, val: u32, pid: u8) {
        self.pid = pid;
        self.raw_hi = val;

        let mut fields: u32 = val;

        self.virtual_page_start = ((fields & EPN_MASK) as u64) << 10;
        fields >>= SIZE_SHIFT;

        let size_field: u8 = (fields & SIZE_MASK) as u8;
        let (size_val, mask) = self.size_bits_to_u64_and_mask(size_field);
        self.virtual_page_end = self.virtual_page_start + size_val;
        self.physical_page_mask = mask;

        fields >>= VALID_SHIFT;

        self.valid = (fields & VALID_MASK) != 0;
    }

    /// Extracts the relevant fields from the data portion of the TLB record.
    pub fn write_low(&mut self, val: u32) {
        self.raw_lo = val;

        let mut fields = val;

        self.physical_page_base = ((fields & RPN_MASK) as u64) << 10;
        fields >>= EX_SHIFT;

        self.exec_enabled = (fields & 0x1) != 0;
        fields >>= WR_SHIFT;

        self.write_enabled = (fields & 0x1) != 0;
    }

    /// Perform translation
    pub fn translate_v_addr(&self, v_addr: u64) -> u64 {
        self.physical_page_base + (v_addr & self.physical_page_mask)
    }
}
