// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    arch_spec::{GeneratorHelp, GeneratorHelper},
    register_manager::RegisterHandleError,
    PcodeBackend,
};

use derivative::Derivative;
use log::{debug, trace, warn};
use styx_cpu_type::{
    arch::backends::{ArchRegister, ArchVariant},
    ArchEndian,
};
use styx_pcode::{
    pcode::{Pcode, SpaceInfo, SpaceName, VarnodeData},
    sla::SlaSpec,
};
use styx_pcode_translator::{
    sla::SlaRegisters, Loader, LoaderRequires, PcodeTranslator, PcodeTranslatorError,
};
use styx_processor::{
    event_controller::EventController,
    memory::{helpers::ReadExt, MemoryOperationError, Mmu, MmuOpError, UnmappedMemoryError},
};

/// Pcode generator implemented by ghidra's libsla.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct GhidraPcodeGenerator {
    #[derivative(Debug = "ignore")]
    /// Internal translator provided by sleigh backend.
    translator: PcodeTranslator<MmuLoader>,

    /// Arch specific helper for changing context variables.
    helper: Option<Box<GeneratorHelper>>,
}

impl GhidraPcodeGenerator {
    pub(crate) fn new<S: SlaSpec + SlaRegisters>(
        arch: &ArchVariant,
        helper: GeneratorHelper,
        loader: MmuLoader,
    ) -> Result<Self, PcodeTranslatorError> {
        let translator = PcodeTranslator::new::<S>(arch, loader)?;

        Ok(Self {
            translator,
            helper: Some(Box::new(helper)),
        })
    }

    pub(crate) fn get_register_rev(
        &self,
        register_varnode: &VarnodeData,
    ) -> Option<&[ArchRegister]> {
        self.translator.get_register_rev(register_varnode)
    }

    pub(crate) fn get_pcode(
        cpu: &mut PcodeBackend,
        address: u64,
        pcodes: &mut Vec<Pcode>,
        data: MmuLoaderDependencies,
    ) -> Result<u64, super::GeneratePcodeError> {
        // execute prefetch routine on generator helper
        let mut helper = cpu.pcode_generator.helper.take().unwrap();
        let context_options = helper.pre_fetch(cpu);
        cpu.pcode_generator.helper = Some(helper);
        // and apply context options
        for option in context_options.into_vec().into_iter() {
            trace!("Setting context option: {option:?}");
            cpu.pcode_generator.translator.set_context_option(option);
        }

        let result = cpu
            .pcode_generator
            .translator
            .get_pcode(address, pcodes, data)?;

        Ok(result)
    }

    pub(crate) fn endian(&self) -> ArchEndian {
        self.translator.endian()
    }

    pub(crate) fn spaces(&self) -> impl Iterator<Item = (SpaceName, SpaceInfo)> {
        self.translator.get_spaces().into_iter()
    }

    pub(crate) fn default_space(&self) -> SpaceName {
        SpaceName::Ram
    }
}

pub(crate) trait RegisterTranslator {
    fn get_register(&self, register: &ArchRegister) -> Option<&VarnodeData>;
    fn get_register_expect(
        &self,
        register: &ArchRegister,
    ) -> Result<&VarnodeData, RegisterHandleError> {
        self.get_register(register)
            .ok_or(RegisterHandleError::CannotHandleRegister(*register))
    }
}

impl RegisterTranslator for GhidraPcodeGenerator {
    fn get_register(&self, register: &ArchRegister) -> Option<&VarnodeData> {
        self.translator.get_register(register)
    }
}

impl GhidraPcodeGenerator {
    // Gets the name of a user op from its index. Useful for reporting unknown
    // and unhandled call others.
    pub fn user_op_name(&self, index: u32) -> Option<&str> {
        self.translator
            .user_ops()
            .iter()
            .find(|user_op| user_op.index == index)
            .map(|op| op.name.as_str())
    }
}

#[derive(Debug)]
struct MmuLoaderRawDependencies {
    mmu: *mut Mmu,
    #[allow(unused)]
    // TODO: finish the MMU implementation so it uses this
    ev: *mut EventController,
    err: *mut Option<MmuOpError>,
}
pub(crate) struct MmuLoaderDependencies<'a> {
    pub mmu: &'a mut Mmu,
    pub ev: &'a mut EventController,
    pub err: &'a mut Option<MmuOpError>,
}

impl<'a> MmuLoaderDependencies<'a> {
    pub(crate) fn new(
        mmu: &'a mut Mmu,
        event_controller: &'a mut EventController,
        err: &'a mut Option<MmuOpError>,
    ) -> Self {
        Self {
            mmu,
            ev: event_controller,
            err,
        }
    }
}

unsafe impl Send for MmuLoader {}
unsafe impl Sync for MmuLoader {}
#[derive(Debug)]
pub(crate) struct MmuLoader(MmuLoaderRawDependencies);
impl LoaderRequires for MmuLoader {
    type LoadRequires<'a> = MmuLoaderDependencies<'a>;

    fn set_data(&mut self, data: Self::LoadRequires<'_>) {
        self.0 = MmuLoaderRawDependencies {
            mmu: std::ptr::from_mut(data.mmu),
            ev: std::ptr::from_mut(data.ev),
            err: std::ptr::from_mut(data.err),
        }
    }
}

impl Default for MmuLoaderRawDependencies {
    fn default() -> Self {
        MmuLoaderRawDependencies {
            mmu: std::ptr::null_mut(),
            ev: std::ptr::null_mut(),
            err: std::ptr::null_mut(),
        }
    }
}
impl MmuLoader {
    pub fn new() -> Self {
        Self(MmuLoaderRawDependencies::default())
    }
}
impl Loader for MmuLoader {
    fn load(&mut self, data_buffer: &mut [u8], addr: u64) {
        data_buffer.fill(0);
        trace!(
            "MmuLoader getting {} bytes from 0x{addr:08X}",
            data_buffer.len()
        );

        // SAFETY: these are set before loader is called
        let mmu = unsafe { &mut *self.0.mmu };
        let upstream_error = unsafe { &mut *self.0.err };

        // now we actually perform the read, and then process
        // the error accordingly
        let read_memory_result = mmu.code().read(addr).bytes(data_buffer);
        trace!("loaded {data_buffer:X?} ");

        // data_buffer is 16 bytes long because ghidra always requests 16 bytes
        // to decode. If we are right against the region boundary or top memory
        // boundary then this could put us over and trigger a
        // [StyxMemoryError::NonContiguousRange] error even though the
        // instruction is contained a valid region.
        let Err(err) = read_memory_result else {
            // Success! Nothing else to do.
            return;
        };

        if let MmuOpError::PhysicalMemoryError(MemoryOperationError::UnmappedMemory(
            UnmappedMemoryError::GoesUnmapped(num_mapped_bytes),
        )) = err
        {
            debug!("MemoryBankLoadImage::load GoesUnmapped @ address: 0x{addr:X}, num_mapped_bytes: {num_mapped_bytes}");

            // this should never panic, as long as GoesUnmapped actually returns the correct amount of mapped bytes
            mmu.code()
                .read(addr)
                .bytes(&mut data_buffer[..num_mapped_bytes as usize])
                .expect("bytes should all be mapped, this indicates GoesUnmapped gave an incorrect number of mapped bytes")
        } else {
            warn!("mmuoperror in pcode translation: {err}, propagating");
            *upstream_error = Some(err);
        }

        trace!("new_buffer {data_buffer:X?} ");
    }
}
#[cfg(test)]
mod tests {
    use styx_processor::{
        event_controller::DummyEventController,
        memory::{memory_region::MemoryRegion, MemoryPermissions},
    };

    use super::*;

    /// Load 16 bytes from memory with plenty of room to spare.
    #[test]
    fn test_load_simple() {
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 100, MemoryPermissions::all(), (0..100).collect())
                .unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies {
            mmu: &mut mmu,
            ev: &mut evt,
            err: &mut err,
        };
        loader.set_data(data);

        let mut data_buffer = [0_u8; 16];
        loader.load(&mut data_buffer, 0);

        assert!(err.is_none());
        assert_eq!(&data_buffer, (0_u8..16).collect::<Vec<_>>().as_slice());
    }

    /// Load 16 bytes from memory but it's on a memory region boundary.
    #[test]
    fn test_load_boundary() {
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 8, MemoryPermissions::all(), (0..8).collect()).unwrap(),
        )
        .unwrap();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(8, 8, MemoryPermissions::all(), (0..8).collect()).unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies {
            mmu: &mut mmu,
            ev: &mut evt,
            err: &mut err,
        };
        loader.set_data(data);

        let mut data_buffer = [0u8; 16];
        loader.load(&mut data_buffer, 0);

        assert!(err.is_none());
        assert_eq!(
            &data_buffer,
            (0u8..8).chain(0u8..8).collect::<Vec<_>>().as_slice()
        );
    }

    /// Load 16 bytes from memory but it's at the top of the range.
    #[test]
    fn test_load_end_of_range() {
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 8, MemoryPermissions::all(), (0..8).collect()).unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies {
            mmu: &mut mmu,
            ev: &mut evt,
            err: &mut err,
        };
        loader.set_data(data);

        let mut data_buffer = [0u8; 16];
        // attempting to load 16 bytes from a 8 byte region, will just fill the first 8
        loader.load(&mut data_buffer, 0);

        assert!(err.is_none());
        assert_eq!(
            &data_buffer,
            (0u8..8)
                .chain([0u8; 8].into_iter())
                .collect::<Vec<_>>()
                .as_slice()
        );
    }

    /// Load 16 bytes from memory but it's at the top of the range.
    #[test]
    fn test_load_completely_out_of_range() {
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 8, MemoryPermissions::all(), (0..8).collect()).unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies {
            mmu: &mut mmu,
            ev: &mut evt,
            err: &mut err,
        };
        loader.set_data(data);

        let mut data_buffer = [0u8; 16];

        // attempting to load completely outside the region
        loader.load(&mut data_buffer, 10);

        // err was thrown
        assert!(err.is_some());
        assert!(matches!(
            err,
            Some(MmuOpError::PhysicalMemoryError(
                MemoryOperationError::UnmappedMemory(UnmappedMemoryError::UnmappedStart(10))
            ))
        ));

        assert_eq!(&data_buffer, &[0u8; 16]);
    }
}
