// SPDX-License-Identifier: BSD-2-Clause
bitflags::bitflags! {
    /// standard section memory permissions
    #[repr(C)]
    pub struct MemoryPermissions : u32 {
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
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
