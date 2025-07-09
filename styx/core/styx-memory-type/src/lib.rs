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
