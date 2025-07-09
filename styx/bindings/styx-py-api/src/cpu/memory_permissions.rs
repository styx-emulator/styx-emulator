// SPDX-License-Identifier: BSD-2-Clause
use pyo3::pyclass;

bitflags::bitflags! {
    #[pyclass(module = "cpu")]
    pub struct MemoryPermissions : u32 {
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
    }
}

/// cbindgen:ignore
const _CHECK_MEMORY_PERMISSIONS: () = {
    assert!(
        MemoryPermissions::all().bits() == styx_emulator::prelude::MemoryPermissions::all().bits(),
        "MemoryPermissions are out of sync!"
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
