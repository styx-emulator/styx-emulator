// SPDX-License-Identifier: BSD-2-Clause
#![allow(dead_code)]
use super::mmu_store::MmuSpace;
use super::sized_value::SizedValue;
use super::space::{Space, SpaceError};
use crate::hooks::{HasHookManager, HookManager};
use crate::pcode_gen::HasPcodeGenerator;
use crate::{HasConfig, PcodeBackend};
use core::panic;
use log::{info, trace, warn};
use smallvec::SmallVec;
use styx_cpu_type::arch::backends::ArchRegister;
use styx_cpu_type::arch::RegisterValue;
use styx_cpu_type::ArchEndian;
use styx_pcode::pcode::{SpaceId, SpaceName, VarnodeData};
use styx_processor::cpu::CpuBackend;
use styx_processor::event_controller::EventController;
use styx_processor::memory::{MemoryOperation, MemoryType, Mmu, MmuOpError};
use thiserror::Error;
use vector_map::VecMap;

/// Owner of pcode machine's [Space]s and provides abstraction for reading and writing to [Space]s.
#[derive(Debug)]
pub struct SpaceManager {
    /// Relation between [SpaceName] and [Space]. Guaranteed to have [SpaceName::Constant] and the
    /// [Self::default_space_name].
    ///
    /// In benchmarks I have found [VecMap] to be significantly faster than a HashMap here and
    /// slightly faster than a BTreeMap.
    spaces: VecMap<SpaceName, Space>,
    mmu_spaces: VecMap<SpaceName, MmuSpace>,
    /// The "default" space as defined by Ghidra Sleigh. Used for load and stores. Typically the Ram
    /// or main processor memory.
    default_space_name: SpaceName,
}

/// Returned from [SpaceManager::new()].
#[derive(Error, Debug)]
pub enum InsertSpaceError {
    #[error("space id {0:?} already in manager")]
    DuplicateSpaceId(SpaceId),
    #[error("space name {0} already in manager")]
    DuplicateSpaceName(SpaceName),
}

#[derive(Error, Debug)]
#[error("space does not exist in space manager")]
pub struct SpaceNotFoundError(SpaceName);

/// Errors from [SpaceManager::read()] and [SpaceManager::write()] calls.
#[derive(Error, Debug)]
pub enum VarnodeError {
    #[error(transparent)]
    SpaceError(#[from] SpaceError),
    #[error(transparent)]
    SpaceNotFound(#[from] SpaceNotFoundError),
}

/// Errors from [SpaceManager::read_chunk()] and [SpaceManager::write_chunk()] calls.
#[derive(Error, Debug)]
pub enum ChunkError {
    #[error(transparent)]
    SpaceMemoryError(#[from] MmuOpError),
    #[error(transparent)]
    SpaceNotFound(#[from] SpaceNotFoundError),
}

pub trait HasSpaceManager {
    fn space_manager(&mut self) -> &mut SpaceManager;
    fn read(&self, varnode: &VarnodeData) -> Result<SizedValue, VarnodeError>;
    fn write(&mut self, varnode: &VarnodeData, data: SizedValue) -> Result<(), VarnodeError>;
}
impl HasSpaceManager for PcodeBackend {
    fn space_manager(&mut self) -> &mut SpaceManager {
        &mut self.space_manager
    }
    fn read(&self, varnode: &VarnodeData) -> Result<SizedValue, VarnodeError> {
        self.space_manager.read(varnode)
    }
    fn write(&mut self, varnode: &VarnodeData, data: SizedValue) -> Result<(), VarnodeError> {
        self.space_manager.write(varnode, data)
    }
}
impl SpaceManager {
    /// Create a new [SpaceManager] with an endianess, a customizable default [Space], and a
    /// preloaded constant space.
    ///
    /// The endianess is used to interpret byte slices from the underlying stores into [SizedValue]s
    /// and integers.
    ///
    /// The `default_space` is the space used for load and store operations.  Typically the
    /// `default_space_name` will be [SpaceName::Ram] but it doesn't necessarily have to be.
    ///
    /// A constant space will always be added with the correct endianness.
    pub fn new(endian: ArchEndian, default_space_name: SpaceName, default_space: MmuSpace) -> Self {
        let spaces = VecMap::new();
        let mmu_spaces = VecMap::new();

        let mut new_self = Self {
            spaces,
            mmu_spaces,
            default_space_name: default_space_name.clone(),
        };

        // add custom default space
        new_self
            .insert_mmu_space(default_space_name, default_space)
            .unwrap();

        // always add const space
        let const_space = Space::new_const(endian);
        new_self
            .insert_space(SpaceName::Constant, const_space)
            .unwrap();

        new_self
    }

    /// Get a space from the manager if it exists.
    ///
    /// Users should prefer [SpaceManager::read()], [SpaceManager::write()], and their hooked
    /// variants over [Space::get_value] or [Space::set_value] as the [SpaceManager]
    /// read/write functions have a simpler API and reduce coupling on the underlying [Space]
    /// implementation.
    fn get_space(&self, name: &SpaceName) -> Result<&Space, SpaceNotFoundError> {
        self.spaces
            .get(name)
            .ok_or(SpaceNotFoundError(name.clone()))
    }

    fn get_space_mut(&mut self, name: &SpaceName) -> Result<&mut Space, SpaceNotFoundError> {
        self.spaces
            .get_mut(name)
            .ok_or(SpaceNotFoundError(name.clone()))
    }
    fn peek_mmu_space(&self, name: &SpaceName) -> Result<&MmuSpace, SpaceNotFoundError> {
        self.mmu_spaces
            .get(name)
            .ok_or(SpaceNotFoundError(name.clone()))
    }
    fn take_mmu_space(&mut self, name: &SpaceName) -> Result<MmuSpace, SpaceNotFoundError> {
        self.mmu_spaces
            .remove(name)
            .ok_or(SpaceNotFoundError(name.clone()))
    }

    fn put_mmu_space(&mut self, name: SpaceName, mmu_space: MmuSpace) {
        self.mmu_spaces.insert(name, mmu_space);
    }

    /// Get reference to the default space.
    pub fn get_default_space_name(&self) -> &SpaceName {
        // Default space will always be present.
        &self.default_space_name
    }

    /// Get [SpaceName] and [Space] reference from ID. Returns [None] if ID not found
    pub fn get_space_name(&self, id: &SpaceId) -> Option<&SpaceName> {
        self.get_space_name_raw(id).or(self.get_space_name_mmu(id))
    }
    fn get_space_name_raw(&self, id: &SpaceId) -> Option<&SpaceName> {
        self.spaces
            .iter()
            .filter_map(|(space_name, space)| {
                if &space.info.id == id {
                    Some(space_name)
                } else {
                    None
                }
            })
            .next()
    }
    fn get_space_name_mmu(&self, id: &SpaceId) -> Option<&SpaceName> {
        self.mmu_spaces
            .iter()
            .filter_map(|(space_name, space)| {
                if &space.info.id == id {
                    Some(space_name)
                } else {
                    None
                }
            })
            .next()
    }
    pub fn get_space_id(&self, name: &SpaceName) -> Option<SpaceId> {
        self.get_space_id_raw(name).or(self.get_space_id_mmu(name))
    }

    fn get_space_id_raw(&self, name: &SpaceName) -> Option<SpaceId> {
        self.spaces
            .iter()
            .filter_map(|(space_name, space)| {
                if space_name == name {
                    Some(space.info.id)
                } else {
                    None
                }
            })
            .next()
    }
    fn get_space_id_mmu(&self, name: &SpaceName) -> Option<SpaceId> {
        self.mmu_spaces
            .iter()
            .filter_map(|(space_name, space)| {
                if space_name == name {
                    Some(space.info.id)
                } else {
                    None
                }
            })
            .next()
    }

    /// checks if the added space has any duplicate name or id
    fn check_dup(&self, id: SpaceId, name: &SpaceName) -> Result<(), InsertSpaceError> {
        // checks if the added space has any duplicate name or id
        if self.get_space_name(&id).is_some() {
            return Err(InsertSpaceError::DuplicateSpaceId(id));
        };
        if self.get_space_id(name).is_some() {
            return Err(InsertSpaceError::DuplicateSpaceName(name.clone()));
        };

        Ok(())
    }

    /// Adds a space to the manager ensuring no duplicate [SpaceName]s or [SpaceId]s are added.
    pub fn insert_space(&mut self, name: SpaceName, space: Space) -> Result<(), InsertSpaceError> {
        info!("Adding space to manager {name}: {space:?}");

        self.check_dup(space.info.id, &name)?;

        self.spaces.insert(name, space);
        Ok(())
    }
    /// Adds a space to the manager ensuring no duplicate [SpaceName]s or [SpaceId]s are added.
    pub fn insert_mmu_space(
        &mut self,
        name: SpaceName,
        space: MmuSpace,
    ) -> Result<(), InsertSpaceError> {
        info!("Adding mmu space to manager {name}: {space:?}");

        self.check_dup(space.info.id, &name)?;

        self.mmu_spaces.insert(name, space);
        Ok(())
    }

    /// Read a Varnode, erroring if the space does not exist or an internal memory error occurs.
    pub fn read(&self, varnode: &VarnodeData) -> Result<SizedValue, VarnodeError> {
        let space = self.get_space(&varnode.space)?;
        Ok(space.get_value(varnode.offset, varnode.size as u8)?)
    }

    /// Writes a Varnode, erroring if the space does not exist or an internal memory error occurs.
    pub fn write(&mut self, varnode: &VarnodeData, data: SizedValue) -> Result<(), VarnodeError> {
        let space = self.get_space_mut(&varnode.space)?;
        Ok(space.set_value(varnode.offset, data)?)
    }

    /// Reads a chunk from a space.
    pub fn read_chunk(
        &self,
        space_name: &SpaceName,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), ChunkError> {
        let space = self.get_space(space_name)?;
        Ok(space.get_chunk(offset, buf)?)
    }

    /// Writes a chunk to a space.
    pub fn write_chunk(
        &mut self,
        space_name: &SpaceName,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), ChunkError> {
        let space = self.get_space_mut(space_name)?;
        Ok(space.set_chunk(offset, buf)?)
    }

    /// Reads a chunk in the default space.
    ///
    /// Useful over [SpaceManager::read_chunk()] because the Error for `x_chunk_default` does not
    /// need to handle [SpaceNotFoundError].
    pub fn read_chunk_default(&self, offset: u64, buf: &mut [u8]) -> Result<(), MmuOpError> {
        self.read_chunk(self.get_default_space_name(), offset, buf)
            .map_err(|err| match err {
                ChunkError::SpaceNotFound(_) => {
                    panic!("Default space not in space manager (very unexpected")
                }
                ChunkError::SpaceMemoryError(err) => err,
            })
    }

    /// Writes a chunk to the default space.
    ///
    /// Useful over [SpaceManager::write_chunk()] because the Error for `x_chunk_default` does not
    /// need to handle [SpaceNotFoundError].
    pub fn write_chunk_default(&mut self, offset: u64, buf: &[u8]) -> Result<(), MmuOpError> {
        let name = self.get_default_space_name().clone();
        self.write_chunk(&name, offset, buf)
            .map_err(|err| match err {
                ChunkError::SpaceNotFound(_) => {
                    panic!("Default space not in space manager (very unexpected)")
                }
                ChunkError::SpaceMemoryError(err) => err,
            })
    }

    /// Reads a varnode from the mmu spaces and triggers ReadMemoryHooks.
    ///
    /// To mimic the Unicorn backend's behavior, we write our modified data bytes (given to the
    /// hook) to memory. It would be nice to not have to do this but the Unicorn read hook
    /// implementation commits the modified bytes to memory so this is required to mock that
    /// behavior.
    ///
    /// TODO: make this return `HookedError` with an UnknownError type to properly propagate errors
    /// from hooks.
    pub fn read_hooked(
        cpu: &mut (impl CpuBackend + MmuSpaceOps + HasSpaceManager + HasHookManager),
        mmu: &mut Mmu,
        ev: &mut EventController,
        varnode: &VarnodeData,
    ) -> Result<SizedValue, VarnodeError> {
        trace!("read_hooked({varnode:?})");
        let endian = cpu
            .space_manager()
            .peek_mmu_space(&varnode.space)?
            .info
            .endian;
        let mut data = cpu.get_value_mmu(mmu, varnode)?.to_bytes(endian);
        let virtual_address = varnode.offset;
        let physical_address = mmu.translate_va(
            virtual_address,
            MemoryOperation::Read,
            MemoryType::Data,
            cpu,
        );

        let original_data = data.clone();
        if let Ok(physical_address) = physical_address {
            HookManager::trigger_memory_read_hook(
                cpu,
                mmu,
                ev,
                physical_address,
                varnode.size,
                &mut data,
            )
            .unwrap();
        } else {
            // this should not get hit because get_value_mmu will error first
            warn!("unexpected error while translating memory read address")
        }

        if original_data != data {
            // Write data changed in memory read hooks back to memory.
            cpu.set_value_mmu(mmu, varnode, SizedValue::from_bytes(&data, endian))?;
        } // Don't write if not changed to match unicorn behavior.

        // finally... read value from memory
        let final_result = cpu.get_value_mmu(mmu, varnode);

        trace!("read hooked {varnode} -> {final_result:?}");
        final_result
    }

    /// Writes a varnode to memory and triggers WriteMemoryHooks.
    ///
    /// To mimic the Unicorn backend's behavior, we always give a slice of 8 bytes to the memory
    /// write hook with the `size` parameter being the actual size of the write.
    pub fn write_hooked(
        cpu: &mut (impl CpuBackend + MmuSpaceOps + HasSpaceManager + HasHookManager),
        mmu: &mut Mmu,
        ev: &mut EventController,
        varnode: &VarnodeData,
        data: SizedValue,
    ) -> Result<(), VarnodeError> {
        let endian = cpu
            .space_manager()
            .peek_mmu_space(&varnode.space)?
            .info
            .endian;

        let data_bytes = data.to_bytes(endian);
        let virtual_address = varnode.offset;
        let physical_address = mmu.translate_va(
            virtual_address,
            MemoryOperation::Write,
            MemoryType::Data,
            cpu,
        );

        if let Ok(physical_address) = physical_address {
            // write_data as bytes for the hook
            HookManager::trigger_memory_write_hook(
                cpu,
                mmu,
                ev,
                physical_address,
                varnode.size,
                &data_bytes,
            )
            .unwrap();
        } else {
            // this should not get hit because set_value_mmu will error first
            warn!("unexpected error while translating memory write address")
        }

        trace!("write hooked at {varnode:?}");

        cpu.set_value_mmu(mmu, varnode, data)
    }

    /// Reads a varnode from the mmu spaces and triggers RegisterRead hooks.
    pub fn read_hooked_register<
        B: CpuBackend
            + HasSpaceManager
            + MmuSpaceOps
            + HasHookManager
            + HasPcodeGenerator<InnerCpuBackend = B>
            + HasConfig
            + 'static,
    >(
        cpu: &mut B,
        mmu: &mut Mmu,
        ev: &mut EventController,
        varnode: &VarnodeData,
    ) -> Result<SizedValue, VarnodeError> {
        if cpu.config().register_read_hooks {
            SpaceManager::read_hooked_register_inner(cpu, mmu, ev, varnode)
        } else {
            cpu.get_value_mmu(mmu, varnode)
        }
    }
    /// Reads a varnode from the mmu spaces and triggers RegisterRead hooks.
    pub fn read_hooked_register_inner<
        B: CpuBackend
            + HasSpaceManager
            + MmuSpaceOps
            + HasHookManager
            + HasPcodeGenerator<InnerCpuBackend = B>
            + HasConfig
            + 'static,
    >(
        cpu: &mut B,
        mmu: &mut Mmu,
        ev: &mut EventController,
        varnode: &VarnodeData,
    ) -> Result<SizedValue, VarnodeError> {
        let data = cpu
            .space_manager()
            .get_space_mut(&varnode.space)?
            .get_value(varnode.offset, varnode.size as u8)?;
        trace!("read_hooked_register({varnode:?}) = {data:?}");
        let registers = cpu.pcode_generator().get_register_rev(varnode);

        let Some(registers) = registers else {
            // varnode is not a register
            return Ok(data);
        };
        // frees cpu ref
        let registers_clone: SmallVec<[ArchRegister; 4]> = registers.iter().cloned().collect();

        let register_value: RegisterValue = data.try_into().unwrap();
        let mut local_register_value = register_value;

        for register in registers_clone.into_iter() {
            trace!("hooking register read {register} with {data:?}");
            HookManager::trigger_register_read_hook(
                cpu,
                mmu,
                ev,
                register,
                &mut local_register_value,
            )
            .unwrap();
        }

        let sized_value: SizedValue = local_register_value.try_into().unwrap();
        debug_assert_eq!(sized_value.size(), varnode.size as u8);
        cpu.space_manager()
            .get_space_mut(&varnode.space)?
            .set_value(varnode.offset, sized_value)
            .unwrap();
        trace!("read reg hook wrote back {sized_value:?}");
        Ok(sized_value)
    }

    /// Reads a varnode from the mmu spaces and triggers RegisterRead hooks.
    pub fn write_hooked_register<
        B: CpuBackend
            + HasSpaceManager
            + MmuSpaceOps
            + HasHookManager
            + HasPcodeGenerator<InnerCpuBackend = B>
            + HasConfig
            + 'static,
    >(
        cpu: &mut B,
        mmu: &mut Mmu,
        ev: &mut EventController,
        varnode: &VarnodeData,
        value_to_write: SizedValue,
    ) -> Result<(), VarnodeError> {
        if cpu.config().register_write_hooks {
            trace!("writing hooked register");
            SpaceManager::write_hooked_register_inner(cpu, mmu, ev, varnode, value_to_write)
        } else {
            cpu.set_value_mmu(mmu, varnode, value_to_write)
        }
    }

    /// Reads a varnode from the mmu spaces and triggers RegisterRead hooks.
    fn write_hooked_register_inner<
        B: CpuBackend
            + HasSpaceManager
            + MmuSpaceOps
            + HasHookManager
            + HasPcodeGenerator<InnerCpuBackend = B>
            + HasConfig
            + 'static,
    >(
        cpu: &mut B,
        mmu: &mut Mmu,
        ev: &mut EventController,
        varnode: &VarnodeData,
        value_to_write: SizedValue,
    ) -> Result<(), VarnodeError> {
        let registers = cpu.pcode_generator().get_register_rev(varnode);

        trace!("in write hooked register inner");
        let Some(registers) = registers else {
            // varnode is not a register
            cpu.space_manager()
                .get_space_mut(&varnode.space)?
                .set_value(varnode.offset, value_to_write)
                .unwrap();
            return Ok(());
        };
        // frees cpu ref
        let registers_clone: SmallVec<[ArchRegister; 4]> = registers.iter().cloned().collect();

        let register_value_to_write: RegisterValue = value_to_write.try_into().unwrap();
        for register in registers_clone.into_iter() {
            HookManager::trigger_register_write_hook(
                cpu,
                mmu,
                ev,
                register,
                &register_value_to_write,
            )
            .unwrap();
        }

        cpu.space_manager()
            .get_space_mut(&varnode.space)?
            .set_value(varnode.offset, value_to_write)
            .unwrap();
        Ok(())
    }

    /// Typical space manager for testing. Default ram space, unique space, and register space.
    #[cfg(test)]
    pub fn create_test_instance(address_size: u64, endian: ArchEndian) -> Self {
        use crate::memory::hash_store::HashStore;
        use styx_pcode::pcode::SpaceInfo;

        let create_info = |id: u64| SpaceInfo {
            word_size: 1,
            address_size,
            endian,
            id: SpaceId::Integer(id),
        };

        let create_store = || HashStore::<1>::new().into();

        let mut space_manager = SpaceManager::new(
            styx_cpu_type::ArchEndian::LittleEndian,
            SpaceName::Ram,
            MmuSpace::new(create_info(1)),
            // Space::from_parts(create_info(1), StyxStore::default().into()),
        );

        space_manager
            .insert_space(
                SpaceName::Unique,
                Space::from_parts(create_info(2), create_store()),
            )
            .unwrap();
        space_manager
            .insert_space(
                SpaceName::Register,
                Space::from_parts(create_info(3), create_store()),
            )
            .unwrap();

        space_manager
    }
}

/// Performs get/set value operations including Mmu spaces.
pub(crate) trait MmuSpaceOps {
    fn get_value_mmu(
        &mut self,
        mmu: &mut Mmu,
        varnode: &VarnodeData,
    ) -> Result<SizedValue, VarnodeError>;

    fn set_value_mmu(
        &mut self,
        mmu: &mut Mmu,
        varnode: &VarnodeData,
        data: SizedValue,
    ) -> Result<(), VarnodeError>;

    fn read_chunk_mmu(
        &mut self,
        mmu: &mut Mmu,
        space_name: &SpaceName,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), ChunkError>;
}

impl MmuSpaceOps for PcodeBackend {
    fn get_value_mmu(
        &mut self,
        mmu: &mut Mmu,
        varnode: &VarnodeData,
    ) -> Result<SizedValue, VarnodeError> {
        Ok(
            if let Ok(space) = self.space_manager.get_space(&varnode.space) {
                space.get_value(varnode.offset, varnode.size as u8)?
            } else {
                let space = self.space_manager.take_mmu_space(&varnode.space)?;
                let res = space.get_value(mmu, self, varnode.offset, varnode.size as u8);
                self.space_manager
                    .put_mmu_space(varnode.space.clone(), space);
                res?
            },
        )
    }

    fn set_value_mmu(
        &mut self,
        mmu: &mut Mmu,
        varnode: &VarnodeData,
        data: SizedValue,
    ) -> Result<(), VarnodeError> {
        if let Ok(space) = self.space_manager.get_space_mut(&varnode.space) {
            space.set_value(varnode.offset, data)?
        } else {
            let space = self.space_manager.take_mmu_space(&varnode.space)?;
            let res = space.set_value(mmu, self, varnode.offset, data);
            self.space_manager
                .put_mmu_space(varnode.space.clone(), space);
            res?;
        };
        Ok(())
    }

    fn read_chunk_mmu(
        &mut self,
        mmu: &mut Mmu,
        space_name: &SpaceName,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), ChunkError> {
        if let Ok(space) = self.space_manager.get_space(space_name) {
            space.get_chunk(offset, buf)?
        } else {
            let space = self.space_manager.take_mmu_space(space_name)?;
            let res = space.get_chunk(mmu, self, offset, buf);
            self.space_manager.put_mmu_space(space_name.clone(), space);
            res?;
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use styx_cpu_type::ArchEndian;
    use styx_pcode::pcode::{AddressSpaceName, SpaceId, SpaceInfo, SpaceName, VarnodeData};

    use crate::memory::{
        blob_store::BlobStore, mmu_store::MmuSpace, sized_value::SizedValue, space::Space,
    };

    use super::SpaceManager;

    #[test]
    fn test_space_manager_simple() {
        let mut manager = SpaceManager::create_test_instance(4, ArchEndian::LittleEndian);

        let varnode = VarnodeData {
            space: SpaceName::Unique,
            offset: 2,
            size: 4,
        };
        manager
            .write(&varnode, SizedValue::from_u128(53, 4))
            .unwrap();

        let value = manager.read(&varnode).unwrap();
        assert_eq!(value.to_u128().unwrap(), 53);
    }

    #[test]
    fn test_space_manager_try_addduplicate_spaces() {
        let mut manager = SpaceManager::create_test_instance(4, ArchEndian::LittleEndian);

        let make_space = |id: u64| {
            Space::from_parts(
                SpaceInfo {
                    word_size: 4,
                    address_size: 4,
                    endian: ArchEndian::LittleEndian,
                    id: SpaceId::from(id),
                },
                BlobStore::new(10).unwrap().into(),
            )
        };
        let make_mmu_space = |id: u64| {
            MmuSpace::new(SpaceInfo {
                word_size: 4,
                address_size: 4,
                endian: ArchEndian::LittleEndian,
                id: SpaceId::from(id),
            })
        };

        // duplicate name
        let new_space = make_space(6);
        let result = manager.insert_space(SpaceName::Unique, new_space);
        assert!(result.is_err());

        // duplicate name
        let new_space = make_space(5);
        let result = manager.insert_space(SpaceName::Ram, new_space);
        assert!(result.is_err());

        // duplicate id
        let new_space = make_space(2);
        let result = manager.insert_space(
            SpaceName::Other(AddressSpaceName::Owned("unique name".into())),
            new_space,
        );
        assert!(result.is_err());

        // duplicate id to mmu
        let new_space = make_mmu_space(2);
        let result = manager.insert_mmu_space(
            SpaceName::Other(AddressSpaceName::Owned("unique name".into())),
            new_space,
        );
        assert!(result.is_err());

        // duplicate name to mmu
        let new_space = make_mmu_space(100);
        let result = manager.insert_mmu_space(SpaceName::Unique, new_space);
        assert!(result.is_err());
    }

    #[test]
    fn test_big_endian() {
        let mut manager = SpaceManager::create_test_instance(4, ArchEndian::BigEndian);

        let varnode = VarnodeData {
            space: SpaceName::Unique,
            offset: 2,
            size: 4,
        };
        manager
            .write(&varnode, SizedValue::from_u128(53, 4))
            .unwrap();

        let value = manager.read(&varnode).unwrap();
        assert_eq!(value.to_u128().unwrap(), 53);
    }
}
