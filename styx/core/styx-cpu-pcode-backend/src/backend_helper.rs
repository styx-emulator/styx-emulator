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
            // This is where we define the backing store for each of the spaces added to the
            // machine, based on their space name. The Ram space is already added above as the
            // default space and has the [StyxStore] memory storage and the
            // [SpaceName::Constant] store added by default.

            // Currently this allocates giant vectors which makes space reads/writes very fast
            // but also theoretically takes a lot of memory. However, Linux's paging system
            // allows us to allocate lots of memory without actually using any physical memory
            // until we access it.

            // This might blow if something writes to all addresses.
            SpaceName::Register => Some(BlobStore::new(REGISTER_SPACE_SIZE).unwrap().into()),
            SpaceName::Ram => None, // Default space already added with [StyxStore]
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

/// The backend helper has common functionality (that has significant overlap) for different PcodeBackends

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

pub trait BackendHelper<T, Q>: CpuBackend + HasHookManager + Sized {
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
    fn stop_requested(&self) -> bool;
    fn set_stop_requested(&mut self, stop_requested: bool);
    fn execute_single(
        &mut self,
        pcodes: &mut Vec<Q>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Result<T, TargetExitReason>, UnknownError>;
    fn set_last_was_branch(&mut self, last_was_branch: bool);
    fn last_was_branch(&mut self) -> bool;

    fn execute_helper(
        &mut self,
        mmu: &mut Mmu,
        event_controller: &mut EventController,
        count: u64,
    ) -> Result<(Option<T>, ExecutionReport), UnknownError> {
        let mut state = MachineState::new(count);
        trace!("Starting pcode machine with max_count={count}");

        // Stop if requested in between ticks
        if self.stop_request_check_and_reset() {
            // self.is_stopped
            return Ok((
                None,
                ExecutionReport::new(TargetExitReason::HostStopRequest, 0),
            ));
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
                    return Ok((
                        None,
                        ExecutionReport::new(reason, state.current_instruction_count),
                    ));
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
        Ok((last_val, exit_reason))
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

    /// Helper
    fn find_first_basic_block(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
        initial_pc: u64,
    ) -> u64;
}
