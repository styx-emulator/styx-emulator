use std::collections::HashMap;

use styx_cpu_type::{
    arch::{
        self,
        backends::{ArchRegister, ArchVariant},
        ArchitectureDef, CpuRegister, RegisterValue,
    },
    ArchEndian,
};
use styx_errors::{styx_cpu::StyxCpuBackendError, UnknownError};
use styx_pcode::pcode::SpaceName;
use styx_processor::{
    cpu::{CpuBackend, ReadRegisterError},
    event_controller::EventController,
    memory::{MemoryOperation, MemoryType, Mmu},
};

use crate::{
    hooks::{HasHookManager, HookManager},
    memory::{
        blob_store::BlobStore, hash_store::HashStore, sized_value::SizedValue, space::Space,
        space_manager::SpaceManager,
    },
    register_manager::RegisterCallbackCpu,
    GhidraPcodeGenerator, MmuSpace, PcodeBackendConfiguration, RegisterManager,
    REGISTER_SPACE_SIZE,
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
