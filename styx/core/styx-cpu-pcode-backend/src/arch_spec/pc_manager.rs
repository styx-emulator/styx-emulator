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

/// Concrete enum for program counter managers.
///
/// In pcode emulation multiple program counters must be kept track of to provide the correct value
/// for hooks and instruction decoding. Additionally, different architectures will have different
/// definitions for what the program counter should be. The [PcManager] solves these problems by
/// providing an architecture agnostic API for defining program counter values.
///
/// Each architecture should implement the [ArchPcManager] trait and supply it to the pcode machine.
#[enum_dispatch(ArchPcManager)]
#[derive(Debug)]
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
    fn set_internal_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
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
    ) -> Result<(), PcOverflow> {
        Ok(())
    }
}

pub(crate) struct PcOverflow;

/// Adds difference to pc.
pub(crate) fn apply_difference(pc: &mut u64, difference: i128) {
    *pc = (*pc as i128 + difference) as u64;
}
