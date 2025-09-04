// SPDX-License-Identifier: BSD-2-Clause
use log::{debug, trace};
use smallvec::SmallVec;
use styx_cpu_type::TargetExitReason;
use styx_errors::{anyhow::Context, UnknownError};
use styx_pcode::pcode::Pcode;
use styx_pcode_translator::ContextOption;
use styx_processor::{
    core::{FetchException, HandleExceptionAction},
    cpu::CpuBackend,
    event_controller::{EventController, ExceptionNumber},
    hooks::{MemFaultData, Resolution},
    memory::{MemoryOperationError, MemoryPermissions, Mmu, MmuOpError},
};
use tap::TryConv;
use thiserror::Error;

use crate::{
    arch_spec::{GeneratorHelp, CONTEXT_OPTION_LEN},
    hooks::{HasHookManager, HookManager},
    pcode_gen::{self, HasPcodeGenerator},
    ArchPcManager, GeneratePcodeError, HasConfig, PcodeBackend,
};

#[derive(Error, Debug)]
pub(crate) enum GetPcodeError {
    #[error(transparent)]
    GeneratePcodeError(#[from] GeneratePcodeError),
    #[error("mmu error while translating pcode {0:?}")]
    MmuOpErr(#[from] MmuOpError),
    #[error(transparent)]
    Other(#[from] UnknownError),
}

#[derive(Clone, Copy)]
pub(crate) enum PcodeFetchException {
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

fn get_pcode_for_pcode_backend(
    cpu: &mut PcodeBackend,
    pcodes: &mut Vec<Pcode>,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<u64, GetPcodeError> {
    let addr = cpu.pc_manager.as_mut().unwrap().internal_pc();
    let mut helper = cpu.pcode_generator.helper.take().unwrap();
    let ctx_opts = helper.pre_fetch(cpu).unwrap();
    cpu.pcode_generator.helper = Some(helper);

    get_pcode_at_address(cpu, addr, pcodes, &ctx_opts, mmu, ev)
}

/// thin wrapper to [GhidraPcodeGenerator::get_pcode].
pub fn get_pcode_at_address<B: CpuBackend + HasPcodeGenerator<InnerCpuBackend = B> + 'static>(
    cpu: &mut B,
    addr: u64,
    pcodes: &mut Vec<Pcode>,
    context_options: &SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<u64, GetPcodeError> {
    pcode_gen::get_pcode(cpu, addr, pcodes, context_options, mmu, ev)
}

#[derive(Error, Debug)]
pub(crate) enum FetchPcodeError {
    #[error("target exit reason encountered while fetching")]
    TargetExit(TargetExitReason),
    #[error("TLB indicated exception")]
    TlbException(ExceptionNumber),
    #[error(transparent)]
    Other(#[from] UnknownError),
}

/// Handle a GetPcodeError by calling the registered hooks.
///
/// We need this separate of fetch_pcode since our Hexagon backend
/// may want to restart its packet-fetching process after this, as opposed to
/// simply fetching again.
pub(crate) fn handle_pcode_exception<
    B: CpuBackend + HasConfig + HasHookManager + HasPcodeGenerator<InnerCpuBackend = B> + 'static,
>(
    cpu: &mut B,
    mmu: &mut Mmu,
    ev: &mut EventController,
    result_err: GetPcodeError,
) -> Result<(TargetExitReason, Resolution), FetchPcodeError> {
    debug!("try_get_pcode error/exception occurred, attempting to recover. Error: {result_err:?}");
    if let GetPcodeError::MmuOpErr(MmuOpError::TlbException(irqn)) = &result_err {
        // tlb exception yahoo!
        return Err(FetchPcodeError::TlbException(*irqn));
    }
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
        HandleExceptionAction::Pause(reason) => return Err(FetchPcodeError::TargetExit(reason)),
        // otherwise, try to handle with hooks
        HandleExceptionAction::TargetHandle(target_exit_reason) => target_exit_reason,
    };

    let pc = cpu.pc()?;
    // now it's only target handling, so we pass to hooks
    Ok((
        target_exit_reason,
        match exception {
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
        },
    ))
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
) -> Result<u64, FetchPcodeError> {
    // attempt to fetch and translate pcodes
    let result = get_pcode_for_pcode_backend(cpu, pcodes, mmu, ev);
    // if success, then return early
    let result_err = match result {
        Ok(success) => return Ok(success),
        Err(err) => err,
    };

    // now we know we encountered an error.
    // this could be an exception that we have to handle or a fatal error
    let (target_exit_reason, did_fix) = handle_pcode_exception(cpu, mmu, ev, result_err)?;

    // if we fixed, try get pcodes again and error if another error occurs.
    trace!("did_fix: {did_fix:?}");
    if did_fix.fixed() {
        let result = get_pcode_for_pcode_backend(cpu, pcodes, mmu, ev);
        match result {
            Ok(bytes_consumed) => Ok(bytes_consumed),
            Err(get_pcode_err) => {
                let exit_reason = get_pcode_err
                    .try_conv::<PcodeFetchException>()?
                    .fetch_exception()
                    .exit_reason();
                Err(FetchPcodeError::TargetExit(exit_reason))
            }
        }
    } else {
        Err(FetchPcodeError::TargetExit(target_exit_reason))
    }
}

/// Generates instruction at address and returns true if branching or if unable to generate (e.g.
/// unmapped memory).
pub(crate) fn is_branching_instruction<
    B: CpuBackend + HasConfig + HasPcodeGenerator<InnerCpuBackend = B> + 'static,
>(
    cpu: &mut B,
    pcodes: &mut Vec<Pcode>,
    context_options: &SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>,
    address: u64,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> (bool, u64) {
    let bytes = match get_pcode_at_address(cpu, address, pcodes, context_options, mmu, ev) {
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
