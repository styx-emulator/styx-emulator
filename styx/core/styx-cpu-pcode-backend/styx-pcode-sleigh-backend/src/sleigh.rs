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
use crate::{
    context_internal::ContextInternal,
    dom::DocumentStorage,
    load_image::{Loader, LoaderRequires, LoaderWrapper, RustLoadImageProxy},
    pcode_emit::{FromFfiVarnode, PCodeEmitRef},
    sleigh_obj::{DeriveParent, SleighObj},
};
use cxx::{let_cxx_string, CxxVector, UniquePtr};
use log::trace;
use std::{collections::HashMap, path::Path};
use std::{pin::Pin, u64};
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
impl<L: Loader + LoaderRequires + 'static> Sleigh<L> {
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

impl<L: Loader + LoaderRequires + 'static> Sleigh<L> {
    /// Translate a single machine instruction at `addr` to list of p-code operations.
    ///
    /// Returns the number of bytes consumed and vector of generated p-code operations.
    pub fn translate(
        &mut self,
        addr: u64,
        pcodes: &mut Vec<Pcode>,
        data: L::LoadRequires<'_>,
    ) -> Result<usize, SleighTranslateError> {
        self._load_image.as_mut().unwrap()._loader.set_data(data);
        let mut emit = PCodeEmitRef::new(&mut self.space_cached, pcodes);
        let mut rust_emit = RustPCodeEmit::from_internal(&mut emit);
        let n = unsafe {
            ffi::sleighOneInstruction(self.obj.as_ref(), (&mut rust_emit) as *mut _, addr)
        }?;

        Ok(n as usize)
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

    pub fn set_variable(&mut self, variable: &str, addr_off: u64, value: u32) {
        let space_manager: &ffi::AddrSpaceManager = self.obj.upcast_ref();
        // TODO: what if code doesn't reside in RAM?
        let_cxx_string!(space_name = "ram");

        cxx::let_cxx_string!(variable_cxx = variable);
        let space = space_manager.getSpaceByName(&space_name);
        let sleigh: Pin<&mut ffi::Sleigh> = self.obj.as_mut();
        // safety: this should get dropped?
        let addr_lo = unsafe { ffi::new_address(space, 0) };
        let addr_hi = unsafe { ffi::new_address(space, u64::MAX) };
        trace!("setting context variable at {}", addr_off);
        sleigh.setContextVariableCached(&variable_cxx, &addr_lo, &addr_hi, value);
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
