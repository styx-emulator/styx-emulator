// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::hooks::Resolution;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CBool(core::ffi::c_int);

impl From<bool> for CBool {
    fn from(value: bool) -> Self {
        Self(if value { 1 } else { 0 })
    }
}

impl From<CBool> for bool {
    fn from(CBool(value): CBool) -> Self {
        value != 0
    }
}

impl From<CBool> for () {
    fn from(_: CBool) -> Self {}
}

impl From<CBool> for Resolution {
    fn from(value: CBool) -> Self {
        let value: bool = value.into();
        match value {
            true => Self::Fixed,
            false => Self::NotFixed,
        }
    }
}
