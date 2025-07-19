// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    arch_spec::{GeneratorHelp, GeneratorHelper},
    get_pcode::GetPcodeError,
    pcode_gen::GeneratePcodeError,
    register_manager::RegisterHandleError,
    PcodeBackend,
};

use derivative::Derivative;
use log::{debug, trace, warn};
use styx_cpu_type::{
    arch::backends::{ArchRegister, ArchVariant},
    ArchEndian,
};
use styx_errors::anyhow::anyhow;
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

use std::collections::HashMap;

/// Pcode generator implemented by ghidra's libsla.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct GhidraPcodeGenerator {
    #[derivative(Debug = "ignore")]
    /// Internal translator provided by sleigh backend.
    translator: Option<PcodeTranslator<MmuLoader>>,

    /// Arch specific helper for changing context variables.
    pub(crate) helper: Option<Box<GeneratorHelper>>,

    /// Cached register storage to support read/write register while the `translator` is in use.
    registers: HashMap<ArchRegister, VarnodeData>,
}

impl GhidraPcodeGenerator {
    pub(crate) fn new<S: SlaSpec + SlaRegisters>(
        arch: &ArchVariant,
        helper: GeneratorHelper,
        loader: MmuLoader,
    ) -> Result<Self, PcodeTranslatorError> {
        let translator = PcodeTranslator::new::<S>(arch, loader)?;
        let registers: HashMap<_, _> = translator
            .get_registers()
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        Ok(Self {
            translator: Some(translator),
            helper: Some(Box::new(helper)),
            registers,
        })
    }

    pub(crate) fn get_register_rev(
        &self,
        register_varnode: &VarnodeData,
    ) -> Option<&[ArchRegister]> {
        self.translator
            .as_ref()
            .map(|t| t.get_register_rev(register_varnode))
            .ok_or(anyhow!("no translator :("))
            .unwrap()
    }

    pub(crate) fn get_pcode(
        cpu: &mut PcodeBackend,
        address: u64,
        pcodes: &mut Vec<Pcode>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<u64, GetPcodeError> {
        // execute prefetch routine on generator helper
        let mut helper = cpu.pcode_generator.helper.take().unwrap();
        let context_options = helper.pre_fetch(cpu)?;
        cpu.pcode_generator.helper = Some(helper);

        let mut err = None;
        let mut translator = cpu
            .pcode_generator
            .translator
            .take()
            .ok_or(anyhow!("no translator :("))
            .unwrap();

        // and apply context options
        for option in context_options.into_iter() {
            trace!("Setting context option: {option:?}");
            translator.set_context_option(option);
        }

        let data = MmuLoaderDependencies::new(cpu, mmu, ev, &mut err);
        let result = translator.get_pcode(address, pcodes, data);
        cpu.pcode_generator.translator = Some(translator);
        if let Some(err) = err {
            Err(GetPcodeError::MmuOpErr(err))
        } else {
            result.map_err(GeneratePcodeError::from).map_err(Into::into)
        }
    }

    pub(crate) fn endian(&self) -> ArchEndian {
        self.translator.as_ref().map(|t| t.endian()).unwrap()
    }

    pub(crate) fn spaces(&self) -> impl Iterator<Item = (SpaceName, SpaceInfo)> {
        self.translator
            .as_ref()
            .map(|t| t.get_spaces().into_iter())
            .unwrap()
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
        self.registers.get(register)
    }
}

impl GhidraPcodeGenerator {
    // Gets the name of a user op from its index. Useful for reporting unknown
    // and unhandled call others.
    pub fn user_op_name(&self, index: u32) -> Option<&str> {
        self.translator
            .as_ref()
            .map(|t| {
                t.user_ops()
                    .iter()
                    .find(|user_op| user_op.index == index)
                    .map(|op| op.name.as_str())
            })
            .unwrap()
    }
}

#[derive(Debug)]
struct MmuLoaderRawDependencies {
    cpu: *mut PcodeBackend,
    mmu: *mut Mmu,
    #[allow(unused)]
    // TODO: finish the MMU implementation so it uses this
    ev: *mut EventController,
    err: *mut Option<MmuOpError>,
}
pub(crate) struct MmuLoaderDependencies<'a> {
    pub cpu: &'a mut PcodeBackend,
    pub mmu: &'a mut Mmu,
    pub ev: &'a mut EventController,
    pub err: &'a mut Option<MmuOpError>,
}

impl<'a> MmuLoaderDependencies<'a> {
    pub(crate) fn new(
        cpu: &'a mut PcodeBackend,
        mmu: &'a mut Mmu,
        event_controller: &'a mut EventController,
        err: &'a mut Option<MmuOpError>,
    ) -> Self {
        Self {
            cpu,
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
            cpu: std::ptr::from_mut(data.cpu),
            mmu: std::ptr::from_mut(data.mmu),
            ev: std::ptr::from_mut(data.ev),
            err: std::ptr::from_mut(data.err),
        }
    }
}

impl Default for MmuLoaderRawDependencies {
    fn default() -> Self {
        MmuLoaderRawDependencies {
            cpu: std::ptr::null_mut(),
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
        let cpu = unsafe { &mut *self.0.cpu };
        let upstream_error = unsafe { &mut *self.0.err };

        // now we actually perform the read, and then process
        // the error accordingly
        let read_memory_result = mmu.virt_code(cpu).read(addr).bytes(data_buffer);
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
            mmu.virt_code(cpu)
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
    use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch};
    use styx_processor::{
        event_controller::DummyEventController,
        memory::{memory_region::MemoryRegion, MemoryPermissions},
    };

    use super::*;

    /// Load 16 bytes from memory with plenty of room to spare.
    #[test]
    fn test_load_simple() {
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 100, MemoryPermissions::all(), (0..100).collect())
                .unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies::new(&mut cpu, &mut mmu, &mut evt, &mut err);
        loader.set_data(data);

        let mut data_buffer = [0_u8; 16];
        loader.load(&mut data_buffer, 0);

        assert!(err.is_none());
        assert_eq!(&data_buffer, (0_u8..16).collect::<Vec<_>>().as_slice());
    }

    /// Load 16 bytes from memory but it's on a memory region boundary.
    #[test]
    fn test_load_boundary() {
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
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
        let data = MmuLoaderDependencies::new(&mut cpu, &mut mmu, &mut evt, &mut err);

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
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 8, MemoryPermissions::all(), (0..8).collect()).unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies::new(&mut cpu, &mut mmu, &mut evt, &mut err);

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
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
        let mut evt = EventController::new(Box::new(DummyEventController::default()));
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(
            MemoryRegion::new_with_data(0, 8, MemoryPermissions::all(), (0..8).collect()).unwrap(),
        )
        .unwrap();

        let mut loader = MmuLoader::new();

        let mut err = None;
        let data = MmuLoaderDependencies::new(&mut cpu, &mut mmu, &mut evt, &mut err);

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
