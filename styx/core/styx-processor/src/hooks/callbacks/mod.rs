// SPDX-License-Identifier: BSD-2-Clause
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
