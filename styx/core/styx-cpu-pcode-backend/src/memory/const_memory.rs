// SPDX-License-Identifier: BSD-2-Clause
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
