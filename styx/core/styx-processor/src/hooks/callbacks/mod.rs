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
mod block;
mod code;
mod interrupt;
mod invalid_instruction;
mod memory_protection;
mod memory_read;
mod memory_unmapped;
mod memory_write;
mod register;

use std::ops::BitAnd;

pub use block::*;
pub use code::*;
pub use interrupt::*;
pub use invalid_instruction::*;
pub use memory_protection::*;
pub use memory_read::*;
pub use memory_unmapped::*;
pub use memory_write::*;
pub use register::*;

/// The type of memory fault that occurred, and any necessary metadata
/// needed to properly handle it
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MemFaultData<'a> {
    Read,
    Write { data: &'a [u8] },
}

/// Indicates if the hook has fixed the occurring issue.
#[derive(Clone, Copy, Debug, Default)]
pub enum Resolution {
    /// Good to go soldier.
    Fixed,
    /// Bro is not fixed 💀
    #[default]
    NotFixed,
}

impl BitAnd for Resolution {
    type Output = Resolution;

    fn bitand(self, rhs: Self) -> Self::Output {
        if self.fixed() || rhs.fixed() {
            Self::Fixed
        } else {
            Self::NotFixed
        }
    }
}

impl Resolution {
    pub fn fixed(self) -> bool {
        match self {
            Resolution::Fixed => true,
            Resolution::NotFixed => false,
        }
    }
}

impl From<bool> for Resolution {
    fn from(value: bool) -> Self {
        match value {
            true => Resolution::Fixed,
            false => Resolution::NotFixed,
        }
    }
}
