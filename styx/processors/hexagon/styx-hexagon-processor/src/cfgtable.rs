// SPDX-License-Identifier: BSD-2-Clause

// The u32 repr is the offset into the cfgtable
#[repr(u32)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub enum HexagonConfigTable {
    L2TCM = 0,
    Etm = 0xc,
    L2Config = 0x10,
    L2InstructionTCM = 0x5C,
    Clade1 = 0x24,
    Clade2 = 0x60,
    // L2 cache tag size?
    L2TagSize = 0x40,
    L2EcomemSize = 0x44,
}
