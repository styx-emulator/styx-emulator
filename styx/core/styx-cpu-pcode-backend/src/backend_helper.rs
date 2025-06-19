// SPDX-License-Identifier: BSD-2-Clause
use std::collections::HashMap;

use log::trace;
use styx_cpu_type::TargetExitReason;
use styx_errors::{anyhow::Context, UnknownError};
use styx_pcode::pcode::SpaceName;
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport},
    event_controller::EventController,
    memory::{MemoryOperation, MemoryType, Mmu},
};

use crate::{
    hooks::{HasHookManager, HookManager},
    memory::{
        blob_store::BlobStore, hash_store::HashStore, space::Space, space_manager::SpaceManager,
    },
    GhidraPcodeGenerator, MachineState, MmuSpace, REGISTER_SPACE_SIZE,
};

/// This sets up the space manager and is where we define the backing store
/// for each of the spaces added to the machine, based on their space name.
/// The Ram space is added as the default space and has the [BlobStore]
/// memory storage and the [SpaceName::Constant] store added by default.
///
/// Currently this allocates giant vectors which makes space reads/writes very fast
/// but also theoretically takes a lot of memory. However, Linux's paging system
/// allows us to allocate lots of memory without actually using any physical memory
/// until we access it.
///
/// Note, [BlobStore] might blow if something writes to all addresses.
pub fn build_space_manager<T: CpuBackend + 'static>(
    pcode_generator: &GhidraPcodeGenerator<T>,
) -> SpaceManager {
    let mut spaces: HashMap<_, _> = pcode_generator.spaces().collect();
    let default = spaces
        .remove(&pcode_generator.default_space())
        .expect("no default space in spaces");

    let default_space = MmuSpace::new(default);

    let mut space_manager = SpaceManager::new(
        pcode_generator.endian(),
        pcode_generator.default_space(),
        default_space,
    );
    for (space_name, space_info) in spaces {
        let space_memory = match space_name {
            SpaceName::Register => Some(BlobStore::new(REGISTER_SPACE_SIZE).unwrap().into()),
            SpaceName::Ram => None, // Default space already added with [BlobStore]
            SpaceName::Constant => None, // Constant space already added from SpaceManager
            SpaceName::Unique => Some(BlobStore::new(u32::MAX as usize).unwrap().into()),
            SpaceName::Other(_) => Some(HashStore::<1>::new().into()),
        };
        if let Some(space_memory) = space_memory {
            let new_space = Space::from_parts(space_info, space_memory);
            space_manager.insert_space(space_name, new_space).unwrap();
        }
    }

    space_manager
}

// The backend helper has common functionality (that has significant overlap) for different PcodeBackends

pub fn pre_execute_hooks<T: CpuBackend + HasHookManager>(
    cpu: &mut T,
    pc: u64,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<(), UnknownError> {
    let physical_pc = mmu.translate_va(pc, MemoryOperation::Read, MemoryType::Code, cpu);
    if let Ok(physical_pc) = physical_pc {
        HookManager::trigger_code_hook(cpu, mmu, ev, physical_pc)?;
    } // no code hook if translate errors, we will catch then on instruction fetch
    Ok(())
}

pub struct BackendHelperExecuteInfo<T> {
    pub report: ExecutionReport,
    pub execute_single_info: Option<T>,
}

/// This helper is a trait that provides some common implementations for
/// executing P-codes across different execution backends to greatly simplify
/// execution logic, which requires handling stop requests, hooks, etc. It can
/// be used to execute P-codes instead of having to write custom logic for every Pcode-based execution
/// backend. It does not handle fetching/decoding P-codes, and the trait's implementation in `execute_single`
/// is expected to call this.
///
/// `BackendHelper` provides a method, `BackendHelper::execute_helper`, that performs
/// all the functionality that `CpuBackend::execute` does. Any `CpuBackend` implementer
/// that wants to take advantage of the common functionality implemented here may simply implement
/// `BackendHelper` and call `BackendHelper::execute_helper` in the implmentation
/// of `CpuBackend::execute`.
///
/// The helper takes in two generics, `ExecuteSingleData` and `PcodesContainer`.
///
/// `ExecuteSingledata` is the return type when execution of a single instruction finishes in
/// `BackendHelper::execute_single`. This is generic as different execution
/// backends may wish to provide different types of data to use when generating
/// the execution report.
///
/// `PcodesContainer` is a container that holds P-codes for different execution backends.
/// The Vec of P-codes passed to `BackendHelper::execute_single` has each element of type `PcodesContainer`.
/// Different backends may choose to hold P-codes differently; the `HexagonPcodeBackend` chooses to set
/// `PcodesContainer` to type `Vec<Pcode>` to have an array of P-codes for each instruction in one larger packet,
/// as `HexagonPcodeBackend` executes packets, not instructions.
///
/// Others may set PodesContainer to type `Pcode`, corresponding to one array of P-codes for one instruction.
///
/// The `BackendHelper::execute_helper` returns the last `ExecuteSingleData` in its
/// `BackendHelperExecuteInfo`, which can be used or discarded in the
/// struct that implements `BackendHelper` and wraps `execute_helper` as
/// described above in its implementation of `CpuBackend`.
pub trait BackendHelper<ExecuteSingleData, PcodesContainer>:
    CpuBackend + HasHookManager + Sized
{
    /// Clears stop_requested and returns the previous result.
    ///
    /// Use this instead of checking the raw value stop_requested to avoid bugs in forgetting to
    /// reset it.
    fn stop_request_check_and_reset(&mut self) -> bool {
        let res = self.stop_requested();
        self.set_stop_requested(false);
        res
    }

    fn pre_execute_hooks(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<(), UnknownError>;

    /// The trait requires the implementation struct to contain a bool field called
    /// `stop_requested`, which is helpful for calling hooks for knowing when to stop execution.
    /// This should read that field.
    fn stop_requested(&self) -> bool;

    /// The trait requires the implementation struct to contain a bool field called
    /// `stop_requested`, which is helpful for calling hooks for knowing when to stop execution.
    /// This should write that field.
    fn set_stop_requested(&mut self, stop_requested: bool);

    /// Execute a single instruction. The `pcodes` passed in will be empty.
    /// The implementation must use the backing program counter,
    /// to fetch/decode pcodes for the current instruction,
    /// and place them into the specified `pcodes` buffer.
    ///
    /// Then, the implementation will execute the sequence of P-codes it fetched and decoded.
    /// If everything executes fully and successfully, the implementation returns `ExecuteSingleData`,
    /// which is an implementation-defined generic containing relevant info about what happened during execution.
    /// The callee may use this information to return a more detailed execution report.
    ///
    /// If execution doesn't finish but errors do not occur, an Ok(Err(TargetExitReason)) is returned,
    /// detailing why execution finished early.
    fn execute_single(
        &mut self,
        pcodes: &mut Vec<PcodesContainer>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Result<ExecuteSingleData, TargetExitReason>, UnknownError>;

    /// The trait requires the implementation struct to contain a bool field called
    /// `last_was_branch`, which is helpful for calling hooks for basic-block detection.
    /// This should write that field.
    fn set_last_was_branch(&mut self, last_was_branch: bool);

    /// The trait requires the implementation struct to contain a bool field called
    /// `last_was_branch`, which is helpful for calling hooks for basic-block detection.
    /// This should read that field.
    fn last_was_branch(&mut self) -> bool;

    /// This contains all execution logic for executing a certain number of
    /// instructions. It is supposed to have the functionality for `CpuBackend::execute`.
    ///
    /// It handles stop requests and various hooks (eg. pre-execute, basic block detected).
    /// If all instruction execute successfully, it returns the last `ExecuteSingleData` from calling
    /// `BackendHelper::execute_single`.
    ///
    /// If more fine-grained control over the `ExecuteSingleData` is desired (eg. using `ExecuteSingleData` from
    /// every execute single to return a different result for an execution report), or a backend desires
    /// to override when/what hooks are called, then this should be overridden.
    fn execute_helper(
        &mut self,
        mmu: &mut Mmu,
        event_controller: &mut EventController,
        count: u64,
    ) -> Result<BackendHelperExecuteInfo<ExecuteSingleData>, UnknownError> {
        let mut state = MachineState::new(count);
        trace!("Starting pcode machine with max_count={count}");

        // Stop if requested in between ticks
        if self.stop_request_check_and_reset() {
            // self.is_stopped
            return Ok(BackendHelperExecuteInfo {
                report: ExecutionReport::new(TargetExitReason::HostStopRequest, 0),
                execute_single_info: None,
            });
        }
        self.set_stop_requested(false);
        let mut current_stop = state.check_done();
        let mut pcodes = Vec::with_capacity(20);
        let mut last_val = None;

        self.set_last_was_branch(false);
        while current_stop.is_none() {
            // call code hooks, can change pc/execution path
            self.pre_execute_hooks(mmu, event_controller)
                .with_context(|| "pre execute hooks failed")
                .unwrap();

            // Stop if requested in code hook
            if self.stop_request_check_and_reset() {
                // self.is_stopped
                current_stop = Some(ExecutionReport::new(
                    TargetExitReason::HostStopRequest,
                    state.current_instruction_count,
                ));
                continue;
            }

            if self.last_was_branch() {
                let pc = self.pc().unwrap();
                self.handle_basic_block_hooks(pc, mmu, event_controller)?;

                self.set_last_was_branch(false);
            }

            pcodes.clear();
            match self.execute_single(&mut pcodes, mmu, event_controller)? {
                Ok(val) => last_val = Some(val),
                Err(reason) => {
                    return Ok(BackendHelperExecuteInfo {
                        execute_single_info: None,
                        report: ExecutionReport::new(reason, state.current_instruction_count),
                    });
                }
            }

            current_stop = state.increment_instruction_count();
            let stop_requested = self.stop_request_check_and_reset();
            trace!("current stop bool: {stop_requested}");
            current_stop = current_stop.or({
                if stop_requested {
                    Some(ExecutionReport::new(
                        TargetExitReason::HostStopRequest,
                        state.current_instruction_count,
                    ))
                } else {
                    None
                }
            })
        }
        let exit_reason = current_stop.unwrap();
        trace!("Exiting due to {exit_reason:?}");
        Ok(BackendHelperExecuteInfo {
            execute_single_info: last_val,
            report: exit_reason,
        })
    }

    /// Run on every "new basic block" meaning after every jump or at the start of execution.
    fn handle_basic_block_hooks(
        &mut self,
        initial_pc: u64,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<(), UnknownError> {
        let block_hook_count = self.hook_manager().block_hook_count()?;
        // Only run basic block hook finding if we have at least one block hook.
        if block_hook_count > 0 {
            let instruction_pc = self.find_first_basic_block(mmu, ev, initial_pc);
            let total_block_size = instruction_pc - initial_pc;

            trace!("total block size is instruction_pc - initial_pc: {total_block_size}");
            HookManager::trigger_block_hook(self, mmu, ev, initial_pc, total_block_size as u32)?;
        }
        Ok(())
    }

    /// This finds the first basic block start after
    /// the current PC specified in `initial_pc`.
    fn find_first_basic_block(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
        initial_pc: u64,
    ) -> u64;
}
