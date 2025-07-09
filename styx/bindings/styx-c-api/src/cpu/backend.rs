// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::core::macros::enum_mirror;

/// All of the supported emulator backends
#[enum_mirror(styx_emulator::core::cpu::Backend)]
#[repr(C)]
pub enum StyxBackend {
    /// A backend that uses Unicorn to emulate the system
    Unicorn,
    /// A backend which uses PCode to emulate the system
    Pcode,
}
