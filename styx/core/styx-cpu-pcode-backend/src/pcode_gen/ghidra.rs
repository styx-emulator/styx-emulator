// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    arch_spec::{GeneratorHelper, CONTEXT_OPTION_LEN},
    get_pcode::GetPcodeError,
    pcode_gen::GeneratePcodeError,
    register_manager::RegisterHandleError,
};

use derivative::Derivative;
use log::{debug, trace, warn};
use smallvec::SmallVec;
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
    sla::SlaRegisters, ContextOption, Loader, LoaderRequires, PcodeTranslator, PcodeTranslatorError,
};
use styx_processor::{
    cpu::CpuBackend,
    event_controller::EventController,
    memory::{helpers::ReadExt, MemoryOperationError, Mmu, MmuOpError, UnmappedMemoryError},
};

use std::collections::HashMap;

use super::HasPcodeGenerator;

/// Pcode generator implemented by ghidra's libsla.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct GhidraPcodeGenerator<T: CpuBackend> {
    #[derivative(Debug = "ignore")]
    /// Internal translator provided by sleigh backend.
    translator: Option<PcodeTranslator<MmuLoader<T>>>,

    /// Arch specific helper for changing context variables.
    pub(crate) helper: Option<Box<GeneratorHelper>>,

    /// Cached register storage to support read/write register while the `translator` is in use.
    registers: HashMap<ArchRegister, VarnodeData>,
}

impl<B: CpuBackend + 'static> GhidraPcodeGenerator<B> {
    pub(crate) fn new<S: SlaSpec + SlaRegisters>(
        arch: &ArchVariant,
        helper: GeneratorHelper,
        loader: MmuLoader<B>,
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

// This should not be dependent on the B generic type of GhidraPcodeGenerator, so we move this out
pub(crate) fn get_pcode<A: CpuBackend + HasPcodeGenerator<InnerCpuBackend = A> + 'static>(
    cpu: &mut A,
    address: u64,
    pcodes: &mut Vec<Pcode>,
    context_options: &SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<u64, GetPcodeError> {
    let mut err = None;
    let mut translator = cpu
        .pcode_generator_mut()
        .translator
        .take()
        .ok_or(anyhow!("no translator :("))
        .unwrap();

    // and apply context options
    for option in context_options.iter() {
        trace!("Setting context option: {option:?}");
        translator.set_context_option(option);
    }

    let data = MmuLoaderDependencies::new(cpu, mmu, ev, &mut err);
    let result = translator.get_pcode(address, pcodes, data);
    cpu.pcode_generator_mut().translator = Some(translator);
    if let Some(err) = err {
        Err(GetPcodeError::MmuOpErr(err))
    } else {
        result.map_err(GeneratePcodeError::from).map_err(Into::into)
    }
}

impl<B: CpuBackend> RegisterTranslator for GhidraPcodeGenerator<B> {
    fn get_register(&self, register: &ArchRegister) -> Option<&VarnodeData> {
        self.registers.get(register)
    }
}

impl<B: CpuBackend + 'static> GhidraPcodeGenerator<B> {
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
struct MmuLoaderRawDependencies<T: CpuBackend> {
    cpu: *mut T,
    mmu: *mut Mmu,
    #[allow(unused)]
    // TODO: finish the MMU implementation so it uses this
    ev: *mut EventController,
    err: *mut Option<MmuOpError>,
}
pub(crate) struct MmuLoaderDependencies<'a, T: CpuBackend> {
    pub cpu: &'a mut T,
    pub mmu: &'a mut Mmu,
    pub ev: &'a mut EventController,
    pub err: &'a mut Option<MmuOpError>,
}

impl<'a, T: CpuBackend> MmuLoaderDependencies<'a, T> {
    pub(crate) fn new(
        cpu: &'a mut T,
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

unsafe impl<T: CpuBackend> Send for MmuLoader<T> {}
unsafe impl<T: CpuBackend> Sync for MmuLoader<T> {}
#[derive(Debug)]
pub(crate) struct MmuLoader<T: CpuBackend>(MmuLoaderRawDependencies<T>);

impl<T: CpuBackend> LoaderRequires for MmuLoader<T> {
    type LoadRequires<'a>
        = MmuLoaderDependencies<'a, T>
    where
        T: 'a;

    fn set_data(&mut self, data: Self::LoadRequires<'_>) {
        self.0 = MmuLoaderRawDependencies {
            cpu: std::ptr::from_mut(data.cpu),
            mmu: std::ptr::from_mut(data.mmu),
            ev: std::ptr::from_mut(data.ev),
            err: std::ptr::from_mut(data.err),
        }
    }
}

impl<T: CpuBackend> Default for MmuLoaderRawDependencies<T> {
    fn default() -> Self {
        MmuLoaderRawDependencies {
            cpu: std::ptr::null_mut(),
            mmu: std::ptr::null_mut(),
            ev: std::ptr::null_mut(),
            err: std::ptr::null_mut(),
        }
    }
}
impl<T: CpuBackend> MmuLoader<T> {
    pub fn new() -> Self {
        Self(MmuLoaderRawDependencies::default())
    }
}
impl<T: CpuBackend> Loader for MmuLoader<T> {
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

    use crate::PcodeBackend;

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
