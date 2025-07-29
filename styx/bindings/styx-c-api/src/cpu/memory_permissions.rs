// SPDX-License-Identifier: BSD-2-Clause

// This is a poor man's bitflags implementation.
// Basically, cbindgen expands macros (configured by `parse.expand.crates` in cbindgen.toml) before
// parsing causing the bitflags macro call to be expanded. Usually cbindgen parses bindgen macro
// calls and parses them to be nice like this but when the expanded form is put through cbindgen
// it is not user friendly.
//
// So until we can exclude certain macros from expanding in cbindgen's macro set, this will have to
// do.
/// standard section memory permissions
#[repr(C)]
pub struct MemoryPermissions {
    bits: u32,
}

impl MemoryPermissions {
    pub const READ: MemoryPermissions = MemoryPermissions { bits: 1 };
    pub const WRITE: MemoryPermissions = MemoryPermissions { bits: 2 };
    pub const EXEC: MemoryPermissions = MemoryPermissions { bits: 4 };

    pub const fn bits(&self) -> u32 {
        self.bits
    }

    pub const fn all() -> Self {
        let bits = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
        MemoryPermissions { bits }
    }

    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self {
            bits: bits & Self::all().bits(),
        }
    }

    pub const fn from_bits(bits: u32) -> Option<Self> {
        let truncated = Self::from_bits_truncate(bits).bits;
        if truncated == bits {
            Some(Self { bits })
        } else {
            None
        }
    }
}

/// this ensures that the memory permissions size doesn't change
/// cbindgen:ignore
const _CHECK_MEMORY_PERMISSIONS: () = {
    assert!(
        MemoryPermissions::all().bits() == styx_emulator::prelude::MemoryPermissions::all().bits(),
        "MemoryPermissions are out of sync!"
    );
    assert!(
        MemoryPermissions::READ.bits() == 1,
        "MemoryPermissions::READ changed",
    );
    assert!(
        MemoryPermissions::WRITE.bits() == 2,
        "MemoryPermissions::WRITE changed",
    );
    assert!(
        MemoryPermissions::EXEC.bits() == 4,
        "MemoryPermissions::EXEC changed",
    );
};

impl From<MemoryPermissions> for styx_emulator::prelude::MemoryPermissions {
    fn from(value: MemoryPermissions) -> Self {
        Self::from_bits(value.bits()).unwrap()
    }
}

impl From<styx_emulator::prelude::MemoryPermissions> for MemoryPermissions {
    fn from(value: styx_emulator::prelude::MemoryPermissions) -> Self {
        Self::from_bits(value.bits()).unwrap()
    }
}
