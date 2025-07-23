// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    context_internal::ContextInternal,
    dom::DocumentStorage,
    load_image::{Loader, LoaderWrapper, RustLoadImageProxy},
    pcode_emit::{FromFfiVarnode, PCodeEmitRef},
    sleigh_obj::{DeriveParent, SleighObj},
};
use cxx::{CxxVector, UniquePtr};
use std::{collections::HashMap, path::Path};
use styx_cpu_type::ArchEndian;
use styx_pcode::pcode::{Pcode, SpaceInfo, SpaceName, VarnodeData};
use styx_sleigh_bindings::{ffi, RustPCodeEmit};
use thiserror::Error;
use vector_map::VecMap;

pub struct Sleigh<L> {
    pub obj: SleighObj<ffi::Sleigh>,
    space_cached: VecMap<u64, SpaceName>,
    _load_image: Option<Box<RustLoadImageProxy<LoaderWrapper<L>>>>,
    _dom: DocumentStorage,
    _context: ContextInternal,
}

// This is probably fine.
unsafe impl<L> Send for Sleigh<L> {}
unsafe impl<L> Sync for Sleigh<L> {}

#[derive(Error, Debug)]
pub enum NewSleighError {
    #[error("sla path not found")]
    InvalidPath,
    #[error("sla file has invalid format: {}", 0)]
    InvalidSla(cxx::Exception),
    #[error("unknown error creating sleigh: {}", 0)]
    UnknownError(cxx::Exception),
}

impl Sleigh<()> {
    pub fn with_context_no_load_image(sla_file: impl AsRef<Path>) -> Self {
        let mut dom = DocumentStorage::with_path(&sla_file).unwrap();

        let context_internal = ContextInternal::default();
        let mut sleigh_obj = SleighObj::from_unique_ptr(unsafe {
            ffi::new_sleigh(std::ptr::null_mut(), context_internal.obj.upcast_raw())
        })
        .unwrap();
        sleigh_obj.as_mut().initialize(dom.obj.as_mut()).unwrap();

        Self {
            obj: sleigh_obj,
            space_cached: VecMap::with_capacity(6),
            _dom: dom,
            _context: context_internal,
            _load_image: None,
        }
    }
}
impl<L: Loader + 'static> Sleigh<L> {
    /// Creates a Sleigh from a [Loader] and sla file path.
    pub fn new(load_image: L, sla_file: impl AsRef<Path>) -> Result<Self, NewSleighError> {
        let sla_file = sla_file.as_ref();
        // sla file exists
        if !sla_file
            .try_exists()
            .map_err(|_| NewSleighError::InvalidPath)?
        {
            return Err(NewSleighError::InvalidPath);
        }

        let mut dom = DocumentStorage::with_path(sla_file).map_err(NewSleighError::UnknownError)?;
        let load_image = Box::new(RustLoadImageProxy::new(LoaderWrapper(load_image)));
        let context_internal = ContextInternal::default();
        let mut sleigh_obj = SleighObj::from_unique_ptr(unsafe {
            ffi::new_sleigh(
                load_image.obj.upcast_raw(),
                context_internal.obj.upcast_raw(),
            )
        })
        .unwrap();
        sleigh_obj
            .as_mut()
            .initialize(dom.obj.as_mut())
            .map_err(NewSleighError::InvalidSla)?;

        Ok(Self {
            obj: sleigh_obj,
            space_cached: VecMap::with_capacity(6),
            _dom: dom,
            _context: context_internal,
            _load_image: Some(load_image),
        })
    }
}

impl<L: Loader + 'static> Sleigh<L> {
    /// Translate a single machine instruction at `addr` to list of p-code operations.
    ///
    /// Returns the number of bytes consumed and vector of generated p-code operations.
    pub fn translate(
        &mut self,
        addr: u64,
        pcodes: &mut Vec<Pcode>,
        data: &mut L::LoadRequires<'_>,
    ) -> Result<usize, SleighTranslateError> {
        unsafe { self._load_image.as_mut().unwrap().loader.set_data(data) };
        let mut emit = PCodeEmitRef::new(&mut self.space_cached, pcodes);
        let mut rust_emit = RustPCodeEmit::from_internal(&mut emit);
        let n = unsafe {
            ffi::sleighOneInstruction(self.obj.as_ref(), (&mut rust_emit) as *mut _, addr)
        }?;

        Ok(n as usize)
    }

    /// A safe way to load data from this sleigh's loader.
    pub fn load(&mut self, addr: u64, data: &mut L::LoadRequires<'_>) -> [u8; 16] {
        let mut data_bytes = [0u8; 16];
        // SAFETY: we hold the LoadRequires mut ref through the load
        unsafe { self._load_image.as_mut().unwrap().loader.set_data(data) };
        let loader = &mut self._load_image.as_mut().unwrap().loader.as_mut().0;
        // mut ref to loader still held
        loader.load(&mut data_bytes, addr);
        data_bytes
    }
}

impl<L> Sleigh<L> {
    pub fn get_register(&mut self, register_name: &str) -> Option<VarnodeData> {
        cxx::let_cxx_string!(register_name_cxx = register_name);

        let varnode = ffi::getRegisterProxy(self.obj.as_ref(), &register_name_cxx).ok()?;

        Some(VarnodeData::from_ffi(varnode))
    }

    pub fn get_spaces(&self) -> HashMap<SpaceName, SpaceInfo> {
        let mut spaces = HashMap::new();
        let space_manager: &ffi::AddrSpaceManager = self.obj.upcast_ref();

        let num_spaces = space_manager.numSpaces();
        for space_idx in 0..num_spaces {
            let ptr = space_manager.getSpace(space_idx);
            let space = unsafe { ptr.as_ref().unwrap() };
            let name: &str = space.getName().to_str().unwrap();
            let space_name = SpaceName::from(name);

            let word_size = space.getWordSize();
            let addr_size = space.getAddrSize();
            let endian = match space.isBigEndian() {
                true => ArchEndian::BigEndian,
                false => ArchEndian::LittleEndian,
            };

            let id = (ptr as u64).into();
            let info = SpaceInfo {
                word_size: word_size as u64,
                address_size: addr_size as u64,
                endian,
                id,
            };

            spaces.insert(space_name, info);
        }

        spaces
    }

    pub fn endian(&self) -> ArchEndian {
        match self.obj.upcast_ref::<ffi::Translate>().isBigEndian() {
            true => ArchEndian::BigEndian,
            false => ArchEndian::LittleEndian,
        }
    }

    pub fn set_variable_default(&mut self, variable: &str, value: u32) {
        self._context.set_variable_default(variable, value);
    }

    /// Get a map between a register's varnode offset and name.
    pub fn get_register_offset_map(&self) -> HashMap<u64, String> {
        let registers: UniquePtr<CxxVector<ffi::RegisterData>> =
            ffi::getRegisters(self.obj.as_ref());

        // Return a map between the varnode offset for the register and the register name.
        registers
            .into_iter()
            .map(|reg| {
                let vnd = VarnodeData::from_ffi(reg.getVarnodeData());
                (vnd.offset, String::from(reg.getName().to_str().unwrap()))
            })
            .collect()
    }

    /// Get the list of available user ops.
    pub fn get_user_ops(&self) -> Vec<UserOpInfo> {
        ffi::getUserOps(self.obj.as_ref())
            .into_iter()
            .map(|userop_data| UserOpInfo {
                index: userop_data.getIndex(),
                name: userop_data.getName().to_str().expect("").to_owned(),
            })
            .collect()
    }
}

/// User op with name and index.
#[derive(Debug, Clone)]
pub struct UserOpInfo {
    pub name: String,
    pub index: u32,
}

// Sleigh < SleighBase < Translate < AddrSpaceManager
unsafe impl DeriveParent<ffi::SleighBase> for SleighObj<ffi::Sleigh> {}
unsafe impl DeriveParent<ffi::Translate> for SleighObj<ffi::Sleigh> {}
unsafe impl DeriveParent<ffi::AddrSpaceManager> for SleighObj<ffi::Sleigh> {}

#[derive(Debug)]
pub enum SleighTranslateError {
    /// Could not translate into an instruction
    BadDataError,
}

impl From<cxx::Exception> for SleighTranslateError {
    fn from(value: cxx::Exception) -> Self {
        match value.what() {
            "BadDataError" => SleighTranslateError::BadDataError,
            _ => panic!("Unknown LowLevelError: {}", value.what()),
        }
    }
}
