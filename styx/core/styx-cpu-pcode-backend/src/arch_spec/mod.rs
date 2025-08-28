// SPDX-License-Identifier: BSD-2-Clause
//! Define architecture behavior where pcode lacks.
//!
//! The Architecture Spec system is a bridge between pcode execution and full architecture emulation. Where
//! pcode's abstractions fall short, the Cpu Spec system takes over and implements missing features
//! almost entirely related to holding processor state.
//!
//! There are four main components:
//! - CallOther Handlers
//! - Register Handlers
//! - A Generator Helper
//! - A Pc Manager
//!
//! CallOther Handlers define code to execute when pcode generates CallOther instructions.
//!
//! Register Handlers define override behavior for register reads and writes.
//!
//! A Generator Helper is called before translating into pcode, allowing for context variables to
//! change.
//!
//! A Pc Manager defines processor counter behavior.
//!

// Architecture implementations
#[cfg(feature = "arch_aarch64")]
mod aarch64;

#[cfg(feature = "arch_arm")]
mod arm;

#[cfg(feature = "arch_bfin")]
mod blackfin;

#[cfg(feature = "arch_ppc")]
mod ppc;

#[cfg(feature = "arch_superh")]
mod superh;

#[cfg(any(feature = "arch_mips32", feature = "arch_mips64"))]
mod mips_common;

#[cfg(feature = "arch_mips32")]
mod mips32;

#[cfg(feature = "arch_mips64")]
mod mips64;

#[cfg(feature = "arch_hexagon")]
mod hexagon;

// Manager types
mod generator_helper;
mod pc_manager;

pub use generator_helper::{GeneratorHelp, GeneratorHelper, CONTEXT_OPTION_LEN};
pub(crate) use pc_manager::{ArchPcManager, PcManager};
use styx_pcode::sla::{SlaSpec, SlaUserOps};
use styx_pcode_translator::sla::SlaRegisters;
use styx_processor::cpu::CpuBackend;

use crate::{
    call_other::{CallOtherManager, UninitCallOtherManager},
    pcode_gen::{GhidraPcodeGenerator, MmuLoader},
    register_manager::RegisterManager,
    PcodeBackend,
};
use styx_cpu_type::{
    arch::{self, backends::ArchVariant},
    ArchEndian,
};

/// "Being built" Arch Spec for architecture builders to modify. After constructing and modifying
/// with arch spec, [build_arch_spec()] will convert to an [ArchSpec].
///
/// Builders can modify these as needed
///
/// ```ignore
/// let mut spec = ArchSpecBuilder::default();
///
/// spec.call_other_manager
///     .add_handler(0, CountLeadingZeros)
///     .unwrap();
///
/// spec.set_pc_manager(ArmThumbPcManager::default());
/// ```
struct ArchSpecBuilder<S, Cpu: CpuBackend> {
    call_other_manager: UninitCallOtherManager<S, Cpu>,
    register_manager: RegisterManager<Cpu>,
    generator_helper: Option<GeneratorHelper>,
    pc_manager: Option<PcManager>,
}
impl<S, Cpu: CpuBackend> Default for ArchSpecBuilder<S, Cpu> {
    fn default() -> Self {
        Self {
            call_other_manager: Default::default(),
            register_manager: Default::default(),
            generator_helper: Default::default(),
            pc_manager: Default::default(),
        }
    }
}

impl<S, Cpu: CpuBackend> ArchSpecBuilder<S, Cpu> {
    /// Set the [GeneratorHelper] implementation, must be done before returning final spec.
    fn set_generator(&mut self, generator: GeneratorHelper) {
        assert!(self.generator_helper.is_none(), "generator already set");
        self.generator_helper = Some(generator);
    }

    /// Set the [PcManager] implementation, must be done before returning final spec.
    fn set_pc_manager(&mut self, pc_manager: PcManager) {
        assert!(self.pc_manager.is_none(), "pc manager already set");
        self.pc_manager = Some(pc_manager);
    }
}

impl<Cpu: CpuBackend + 'static, S: SlaSpec + SlaUserOps + SlaRegisters> ArchSpecBuilder<S, Cpu> {
    fn build(self, arch: &ArchVariant) -> ArchSpec<Cpu> {
        let loader = MmuLoader::new();
        let generator_helper = self.generator_helper.expect("generator was not set");
        let pcode_generator = GhidraPcodeGenerator::new::<S>(arch, generator_helper, loader)
            .expect("could not create GhidraPcodeGenerator");

        // Make finalized arch spec
        ArchSpec {
            call_other: self.call_other_manager.init(),
            register: self.register_manager,
            generator: pcode_generator,
            pc_manager: self.pc_manager.expect("pc manager was not set"),
        }
    }
}

/// Create an architecture spec from a requested architecture.
pub fn build_arch_spec(arch: &ArchVariant, endian: ArchEndian) -> ArchSpec<PcodeBackend> {
    match arch {
        #[cfg(feature = "arch_arm")]
        ArchVariant::Arm(variant) => arm::arm_arch_spec(arch, variant, endian),

        #[cfg(feature = "arch_aarch64")]
        ArchVariant::Aarch64(variant) => match variant {
            arch::aarch64::Aarch64MetaVariants::Generic(_) => aarch64::generic::build(),
        }
        .build(arch),

        #[cfg(feature = "arch_bfin")]
        ArchVariant::Blackfin(variant) => match variant {
            arch::blackfin::BlackfinMetaVariants::Bf535(_) => todo!("BF535 has special considerations that must be followed, see Appendix A of the Blackfin Processor Programming Reference Manual"),
            _ => blackfin::bf5xx::build(),
        }
        .build(arch),

        #[cfg(feature = "arch_superh")]
        ArchVariant::SuperH(variant) => match variant {
            arch::superh::SuperHMetaVariants::SH1(_) => superh::sh1::build().build(arch),
            arch::superh::SuperHMetaVariants::SH2(_) => superh::sh2::build().build(arch),
            arch::superh::SuperHMetaVariants::SH2A(_) => superh::sh2a::build().build(arch),
            arch::superh::SuperHMetaVariants::SH4(_) => superh::sh4eb::build().build(arch),
            _ => unimplemented!("SH variant {variant:?} not explicitly supported by pcode backend, please reach out to dev team"),
        },

        #[cfg(feature = "arch_ppc")]
        ArchVariant::Ppc32(arch::ppc32::Ppc32MetaVariants::Ppc401(_)  | arch::ppc32::Ppc32MetaVariants::Ppc405(_) | arch::ppc32::Ppc32MetaVariants::Ppc440(_) | arch::ppc32::Ppc32MetaVariants::Ppc470(_)) => ppc::ppc4xx::build().build(arch),

        #[cfg(feature = "arch_mips32")]
        ArchVariant::Mips32(_) => mips32::mips32_arch_spec(arch, endian).unwrap(),

        #[cfg(feature = "arch_mips64")]
        ArchVariant::Mips64(_) => mips64::mips64_arch_spec(arch, endian).unwrap(),

        #[cfg(feature = "arch_hexagon")]
        ArchVariant::Hexagon(arch::hexagon::HexagonMetaVariants::QDSP6V60(_)  |
                             arch::hexagon::HexagonMetaVariants::QDSP6V62(_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V65 (_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V66(_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V67(_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V67T(_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V69(_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V71 (_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V73 (_) |
                             arch::hexagon::HexagonMetaVariants::QDSP6V77(_) ) => hexagon::build().build(arch),

        _ => unimplemented!("architecture {arch:?} not supported by pcode backend"),
    }
}

/// Finalized arch spec consume by [crate::PcodeBackend].
pub struct ArchSpec<Cpu>
where
    Cpu: CpuBackend,
{
    pub call_other: CallOtherManager<Cpu>,
    pub register: RegisterManager<Cpu>,
    pub generator: GhidraPcodeGenerator<Cpu>,
    pub pc_manager: PcManager,
}
