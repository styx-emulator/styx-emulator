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
use log::{debug, trace};
use styx_cpu_type::TargetExitReason;
use styx_errors::{anyhow::Context, UnknownError};
use styx_pcode::pcode::Pcode;
use styx_processor::{
    core::{FetchException, HandleExceptionAction},
    cpu::CpuBackend,
    event_controller::EventController,
    hooks::MemFaultData,
    memory::{MemoryOperationError, MemoryPermissions, Mmu, MmuOpError},
};
use tap::TryConv;
use thiserror::Error;

use crate::{
    hooks::HookManager, ArchPcManager, GeneratePcodeError, GhidraPcodeGenerator, HasConfig,
    MmuLoaderDependencies, PcodeBackend,
};

#[derive(Error, Debug)]
enum GetPcodeError {
    #[error(transparent)]
    GeneratePcodeError(#[from] GeneratePcodeError),
    #[error("mmu error while translating pcode {0:?}")]
    MmuOpErr(#[from] MmuOpError),
    #[error(transparent)]
    Other(#[from] UnknownError),
}

#[derive(Clone, Copy)]
enum PcodeFetchException {
    ProtectedMemoryFetch { have: MemoryPermissions },
    UnmappedMemoryFetch,
    InvalidInstruction,
}
impl PcodeFetchException {
    pub fn fetch_exception(self) -> FetchException {
        self.into()
    }
}
impl From<PcodeFetchException> for FetchException {
    fn from(value: PcodeFetchException) -> Self {
        match value {
            PcodeFetchException::ProtectedMemoryFetch { .. } => {
                FetchException::ProtectedMemoryFetch
            }
            PcodeFetchException::UnmappedMemoryFetch => FetchException::UnmappedMemoryFetch,
            PcodeFetchException::InvalidInstruction => FetchException::InvalidInstruction,
        }
    }
}

impl TryFrom<GetPcodeError> for PcodeFetchException {
    type Error = UnknownError;
    fn try_from(value: GetPcodeError) -> Result<Self, UnknownError> {
        match value {
            GetPcodeError::GeneratePcodeError(GeneratePcodeError::InvalidInstruction) => {
                Ok(PcodeFetchException::InvalidInstruction)
            }
            GetPcodeError::MmuOpErr(MmuOpError::PhysicalMemoryError(
                MemoryOperationError::UnmappedMemory(_),
            )) => Ok(PcodeFetchException::UnmappedMemoryFetch),
            GetPcodeError::MmuOpErr(MmuOpError::PhysicalMemoryError(
                MemoryOperationError::InvalidRegionPermissions { have, need: _ },
            )) => Ok(PcodeFetchException::ProtectedMemoryFetch { have }),
            other => Err(other).context("unknown error while translating pcode"),
        }
    }
}

/// thin wrapper to [GhidraPcodeGenerator::get_pcode].
fn get_pcode_at_address(
    cpu: &mut PcodeBackend,
    addr: u64,
    pcodes: &mut Vec<Pcode>,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<u64, GetPcodeError> {
    let mut err = None;
    let data = MmuLoaderDependencies::new(mmu, ev, &mut err);
    let pcode_res = GhidraPcodeGenerator::get_pcode(cpu, addr, pcodes, data);
    if let Some(err) = err {
        Err(GetPcodeError::MmuOpErr(err))
    } else {
        pcode_res.map_err(Into::into)
    }
}

/// Grab the pcodes at the current program counter
fn get_pcode_at_pc(
    cpu: &mut PcodeBackend,
    mmu: &mut Mmu,
    ev: &mut EventController,
    pcodes: &mut Vec<Pcode>,
) -> Result<u64, GetPcodeError> {
    // pc in separate expression so pc_manager lock is dropped before executing code hook
    let pc = cpu
        .pc_manager
        .as_ref()
        .context("pc manager is None, this indicates a bug in the pcode backend")?
        .internal_pc();
    get_pcode_at_address(cpu, pc, pcodes, mmu, ev)
}

/// Fetches bytes from memory, translates into pcode, and digests into backend friendly errors.
///
/// A top level `Err(UnknownError)` indicates a fatal error.
///
/// A Ok(Err(exit_reason)) indicates the fetch_pcode triggered an exception and the emulator should
/// pause with the given exception.
///
/// A Ok(Ok(u64)) indicates pcodes were successfully fetched and `n` bytes were read.
///
/// On success, `pcodes` will have the translated pcodes appended to it.
pub(crate) fn fetch_pcode(
    cpu: &mut PcodeBackend,
    pcodes: &mut Vec<Pcode>,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<Result<u64, TargetExitReason>, UnknownError> {
    // attempt to fetch and translate pcodes
    let result = get_pcode_at_pc(cpu, mmu, ev, pcodes);
    // if success, then return early
    let result_err = match result {
        Ok(success) => return Ok(Ok(success)),
        Err(err) => err,
    };

    // now we know we encountered an error.
    // this could be an exception that we have to handle or a fatal error
    debug!("try_get_pcode error/exception occurred, attempting to recover. Error: {result_err:?}");
    let exception: PcodeFetchException = result_err
        .try_into()
        .context("unknown error while translating pcode")?; // return early if fatal

    // now we know its an exception, let's ask the ExceptionBehavior to see what to do
    let action = cpu
        .config()
        .exception
        .handle_exception(exception.fetch_exception().into());

    debug!("exception behavior determined them following action: {action:?}");
    let target_exit_reason = match action {
        // requested action is to pause emulation, DO NOT try to handle. thus, we return early
        HandleExceptionAction::Pause(target_exit_reason) => return Ok(Err(target_exit_reason)),
        // otherwise, try to handle with hooks
        HandleExceptionAction::TargetHandle(target_exit_reason) => target_exit_reason,
    };

    let pc = cpu.pc()?;
    // now it's only target handling, so we pass to hooks
    let did_fix = match exception {
        PcodeFetchException::ProtectedMemoryFetch { have } => {
            // Size of 16 here because we don't know the target instruction size and the pcode
            // translator reads 16 bytes to translate pcodes
            HookManager::trigger_protection_fault_hook(
                cpu,
                mmu,
                ev,
                pc,
                16,
                have,
                MemFaultData::Read,
            )?
        }
        PcodeFetchException::InvalidInstruction => {
            HookManager::trigger_invalid_instruction_hook(cpu, mmu, ev)?
        }
        PcodeFetchException::UnmappedMemoryFetch => {
            // Size of 16 here because we don't know the target instruction size and the pcode
            // translator reads 16 bytes to translate pcodes
            HookManager::trigger_unmapped_fault_hook(cpu, mmu, ev, pc, 16, MemFaultData::Read)?
        }
    };

    // if we fixed, try get pcodes again and error if another error occurs.
    trace!("did_fix: {did_fix:?}");
    if did_fix.fixed() {
        let result = get_pcode_at_pc(cpu, mmu, ev, pcodes);
        match result {
            Ok(a) => Ok(Ok(a)),
            Err(b) => Ok(Err(b
                .try_conv::<PcodeFetchException>()?
                .fetch_exception()
                .exit_reason())),
        }
    } else {
        Ok(Err(target_exit_reason))
    }
}

/// Generates instruction at address and returns true if branching or if unable to generate (e.g.
/// unmapped memory).
pub(crate) fn is_branching_instruction(
    cpu: &mut PcodeBackend,
    pcodes: &mut Vec<Pcode>,
    address: u64,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> (bool, u64) {
    let bytes = match get_pcode_at_address(cpu, address, pcodes, mmu, ev) {
        Ok(success) => success,
        _ => {
            // Failed decompile, end of basic block
            return (true, 0);
        }
    };
    (contains_branch_instruction(pcodes), bytes)
}

/// Returns true if any op in the pcodes is a branching instruction.
fn contains_branch_instruction(pcodes: &[Pcode]) -> bool {
    pcodes.iter().any(|p| p.is_branch())
}
