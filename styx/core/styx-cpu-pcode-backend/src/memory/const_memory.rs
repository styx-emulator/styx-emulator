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
use super::space::IsSpaceMemory;
use styx_cpu_type::ArchEndian;
use styx_processor::memory::MmuOpError;

/// [IsSpaceMemory] for the Constant address space.
///
/// The constant address space is defined such that offsets into this space return the offset
/// itself.
///
/// This must hold the endianness of the containing address space because the numeric result data is
/// returned as a byte array and we need to know what byte order is going to be used to reconstruct
/// the numeric result.
#[derive(Debug)]
pub struct ConstMemory {
    endian: ArchEndian,
}

impl ConstMemory {
    /// Create a new [ConstMemory] with a matching endianness of the containing space.
    ///
    /// The given `endian` must match the containing space.
    pub fn new(endian: ArchEndian) -> Self {
        Self { endian }
    }
}

impl IsSpaceMemory for ConstMemory {
    fn get_chunk(&self, offset: u64, buf: &mut [u8]) -> Result<(), MmuOpError> {
        let buf_len = buf.len();
        debug_assert!(buf_len <= 8);

        let sized_bytes = match self.endian {
            ArchEndian::LittleEndian => &offset.to_le_bytes()[0..buf_len],
            ArchEndian::BigEndian => &offset.to_be_bytes()[(8 - buf_len)..8],
        };
        buf.copy_from_slice(sized_bytes);

        Ok(())
    }

    fn set_chunk(&mut self, _offset: u64, _buf: &[u8]) -> Result<(), MmuOpError> {
        panic!("Write to constant space.");
    }
}

// Tests for ConstMemory are in the tests for [super::space] because it is easier to compare values from
// there rather than reconstruct byte arrays.
