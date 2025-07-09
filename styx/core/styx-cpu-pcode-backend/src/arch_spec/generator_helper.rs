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
use crate::PcodeBackend;
use enum_dispatch::enum_dispatch;
use std::fmt::Debug;
use styx_pcode_translator::ContextOption;

#[cfg(feature = "arch_aarch64")]
use super::aarch64;

#[cfg(feature = "arch_arm")]
use super::arm;

#[cfg(feature = "arch_superh")]
use super::superh;

/// Arch specific customization pcode generators.
#[enum_dispatch]
pub trait GeneratorHelp: Debug {
    /// Called before fetching instructions, returns a list of [ContextOption] to apply. Should be
    /// fairly quick as this is called on every pcode translate call.
    ///
    /// FIXME: possible change return type to stack only buffer to reduce allocations.
    fn pre_fetch(&mut self, backend: &mut PcodeBackend) -> Box<[ContextOption]>;
}

/// Use [GeneratorHelper::default()] for a "do-nothing" helper.
#[enum_dispatch(GeneratorHelp)]
#[derive(Debug)]
pub enum GeneratorHelper {
    #[cfg(feature = "arch_aarch64")]
    Aarch64(aarch64::StandardGeneratorHelper),
    #[cfg(feature = "arch_arm")]
    Arm(arm::StandardGeneratorHelper),
    #[cfg(feature = "arch_arm")]
    ArmThumb(arm::ThumbOnlyGeneratorHelper),
    Empty(EmptyGeneratorHelper),
    #[cfg(feature = "arch_superh")]
    SuperH(superh::StandardGeneratorHelper),
}

impl Default for GeneratorHelper {
    fn default() -> Self {
        Self::Empty(EmptyGeneratorHelper)
    }
}

/// [GeneratorHelp] that does nothing.
#[derive(Debug, Default)]
pub struct EmptyGeneratorHelper;
impl GeneratorHelp for EmptyGeneratorHelper {
    fn pre_fetch(&mut self, _backend: &mut PcodeBackend) -> Box<[ContextOption]> {
        [].into()
    }
}
