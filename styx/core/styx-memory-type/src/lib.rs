// SPDX-License-Identifier: BSD-2-Clause
use bitflags::bitflags;
use derive_more::Display;

/// Enum that is used to be explicit in error handling
/// of current memory operations
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
pub enum MemoryOperation {
    Read,
    Write,
}

bitflags! {
    #[repr(C)]
    #[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub struct MemoryPermissions : u32 {
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const RW = Self::READ.bits() | Self::WRITE.bits();
        const RX = Self::READ.bits() | Self::EXEC.bits();
    }
}

impl std::fmt::Display for MemoryPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.contains(Self::READ) { "R" } else { "-" },
            if self.contains(Self::WRITE) { "W" } else { "-" },
            if self.contains(Self::EXEC) { "X" } else { "-" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_permissions_display() {
        assert_eq!(format!("{}", MemoryPermissions::READ), String::from("R--"));
        assert_eq!(format!("{}", MemoryPermissions::WRITE), String::from("-W-"));
        assert_eq!(format!("{}", MemoryPermissions::EXEC), String::from("--X"));
        assert_eq!(format!("{}", MemoryPermissions::RW), String::from("RW-"));
        assert_eq!(format!("{}", MemoryPermissions::RX), String::from("R-X"));
        assert_eq!(
            format!("{}", MemoryPermissions::WRITE | MemoryPermissions::EXEC),
            String::from("-WX")
        );
        assert_eq!(format!("{}", MemoryPermissions::all()), String::from("RWX"));
    }
}
