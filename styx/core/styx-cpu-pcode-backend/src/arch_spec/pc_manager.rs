// SPDX-License-Identifier: BSD-2-Clause
use crate::PcodeBackend;
use enum_dispatch::enum_dispatch;
use smallvec::SmallVec;
use std::fmt::Debug;

#[cfg(feature = "arch_aarch64")]
use super::aarch64;

#[cfg(feature = "arch_arm")]
use super::arm;

#[cfg(feature = "arch_bfin")]
use super::blackfin;

#[cfg(feature = "arch_superh")]
use super::superh;

#[cfg(feature = "arch_ppc")]
use super::ppc;

#[cfg(any(feature = "arch_mips32", feature = "arch_mips64"))]
use super::mips_common;

#[cfg(feature = "arch_hexagon")]
use super::hexagon;

/// Concrete enum for program counter managers.
///
/// In pcode emulation multiple program counters must be kept track of to provide the correct value
/// for hooks and instruction decoding. Additionally, different architectures will have different
/// definitions for what the program counter should be. The [PcManager] solves these problems by
/// providing an architecture agnostic API for defining program counter values.
///
/// Each architecture should implement the [ArchPcManager] trait and supply it to the pcode machine.
#[enum_dispatch(ArchPcManager)]
// We derive Clone here because the PcManager
// is saved and restored in context_save and
// context_restore using .clone().
#[derive(Debug, Clone)]
pub enum PcManager {
    #[cfg(feature = "arch_aarch64")]
    Aarch64(aarch64::StandardPcManager),
    #[cfg(feature = "arch_arm")]
    ArmThumb(arm::ThumbPcManager),
    #[cfg(feature = "arch_arm")]
    Arm(arm::StandardPcManager),
    #[cfg(feature = "arch_bfin")]
    Blackfin(blackfin::StandardPcManager),
    #[cfg(feature = "arch_ppc")]
    Ppc(ppc::StandardPpcPcManager),
    #[cfg(feature = "arch_superh")]
    SuperH(superh::StandardPcManager),
    #[cfg(any(feature = "arch_mips32", feature = "arch_mips64"))]
    Mips(mips_common::StandardMipsPcManager),
    #[cfg(feature = "arch_hexagon")]
    Hexagon(hexagon::StandardPcManager),
}

/// Implemented for structs that can manager the pcode machine program counters.
///
/// A pc manager acts as a state machine, with methods called at different parts of the
/// fetch-translate-execute sequence.
///
/// See [PcManager] for concrete implementations.
#[enum_dispatch]
pub(crate) trait ArchPcManager: Debug {
    /// Value of Program Counter as defined by the Instruction Set Architecture.
    ///
    /// This is the pc that is read inside machine instructions like `mov r0, pc`. This is also the
    /// pc that is returned from [styx_processor::cpu::CpuBackend::pc()].
    fn isa_pc(&self) -> u64;
    /// Value of Program Counter for internal backend use. Used to track the next instruction to
    /// translate and execute.
    ///
    /// This pc must hold the following: before execution the PC points to the next instruction,
    /// during fetch and execution this is set to the current instruction. After execution the PC is
    /// set to the next instruction to be executed.
    ///
    /// This pc is to track the next instruction to translate and execute.
    fn internal_pc(&self) -> u64 {
        self.isa_pc()
    }

    /// Sets the isa program counter to `value`, NOTE: the internal counter must be kept in sync
    /// with this counter!
    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend);
    /// Sets the internal program counter to `value`. NOTE: the ISA counter must be kept in sync
    /// with this counter!
    fn set_internal_pc(&mut self, value: u64, backend: &mut PcodeBackend, _from_branch: bool) {
        self.set_isa_pc(value, backend)
    }

    /// Called before executing the code hook.
    fn pre_code_hook(&mut self, _backend: &mut PcodeBackend) {}
    /// Called before fetching the next instruction. Instruction fetching uses the internal pc.
    fn pre_fetch(&mut self, _backend: &mut PcodeBackend) -> Result<(), PcOverflow> {
        Ok(())
    }
    /// Called after fetching the instruction.
    ///
    /// Can return `Err(PcOverflow)` to indicate that the pc has overflowed and to halt the
    /// processor with an error.
    fn post_fetch(&mut self, _bytes_consumed: u64, _backend: &mut PcodeBackend) {}
    /// Called after executing the instruction.
    ///
    /// Will not get called if the cpu halts because of an unmapped memory or protected memory
    /// exception.
    ///
    /// Can return `Err(PcOverflow)` to indicate that the pc has overflowed and to halt the
    /// processor with an error.
    fn post_execute(
        &mut self,
        _bytes_consumed: u64,
        _backend: &mut PcodeBackend,
        _regs_written: &mut SmallVec<[u64; 3]>,
        _total_pcodes: usize,
    ) -> Result<(), PcOverflow> {
        Ok(())
    }
}

pub(crate) struct PcOverflow;

/// Adds difference to pc.
pub(crate) fn apply_difference(pc: &mut u64, difference: i128) {
    *pc = (*pc as i128 + difference) as u64;
}
