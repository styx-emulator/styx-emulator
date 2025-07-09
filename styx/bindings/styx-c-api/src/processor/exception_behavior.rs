// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::core::macros::enum_mirror;

/// The behavior an emulator should use in case of exceptional behavior
#[enum_mirror(styx_emulator::core::core::ExceptionBehavior)]
#[repr(C)]
pub enum StyxExceptionBehavior {
    Panic,
    Raise,
    TargetHandle,
    Pause,
}
