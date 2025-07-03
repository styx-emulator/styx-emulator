// SPDX-License-Identifier: BSD-2-Clause
use crate::{pcode_gen::GeneratePcodeError, PcodeBackend};
use enum_dispatch::enum_dispatch;
use smallvec::{smallvec, SmallVec};
use std::fmt::Debug;
use styx_pcode_translator::ContextOption;
use styx_processor::memory::Mmu;

#[cfg(feature = "arch_aarch64")]
use super::aarch64;

#[cfg(feature = "arch_arm")]
use super::arm;

use super::hexagon;
#[cfg(feature = "arch_superh")]
use super::superh;

pub const CONTEXT_OPTION_LEN: usize = 4;

/// Arch specific customization pcode generators.
#[enum_dispatch]
pub trait GeneratorHelp: Debug {
    /// Called before fetching instructions, returns a list of [ContextOption] to apply. Should be
    /// fairly quick as this is called on every pcode translate call.
    ///
    /// FIXME: possible change return type to stack only buffer to reduce allocations.
    fn pre_fetch(
        &mut self,
        backend: &mut PcodeBackend,
        mmu: &mut Mmu,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError>;
}

/// Use [GeneratorHelper::default()] for a "do-nothing" helper.
#[enum_dispatch(GeneratorHelp)]
// We derive Clone here because the GeneratorHelper
// is saved and restored in context_save and
// context_restore using .clone().
#[derive(Debug, Clone)]
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
    #[cfg(feature = "arch_hexagon")]
    Hexagon(hexagon::HexagonGeneratorHelper),
}

impl Default for GeneratorHelper {
    fn default() -> Self {
        Self::Empty(EmptyGeneratorHelper)
    }
}

/// [GeneratorHelp] that does nothing.
#[derive(Debug, Default, Clone)]
pub struct EmptyGeneratorHelper;
impl GeneratorHelp for EmptyGeneratorHelper {
    fn pre_fetch(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError> {
        Ok(smallvec![])
    }
}
