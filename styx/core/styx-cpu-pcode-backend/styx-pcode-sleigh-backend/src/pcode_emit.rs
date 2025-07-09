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
use cxx::CxxVector;
use smallvec::SmallVec;
use styx_pcode::pcode::{Pcode, SpaceName, VarnodeData};
use styx_sleigh_bindings::ffi;
use vector_map::VecMap;

/// Methods for converting [ffi::VarnodeData] into [VarnodeData].
pub trait FromFfiVarnode {
    /// Converts by caching space pointer -> [SpaceName] mappings only falling back to string
    /// parsing when an unrecognized space pointer is found.
    fn from_ffi_space_ptr_cache(
        spaces_ptr: &mut VecMap<u64, SpaceName>,
        var: &ffi::VarnodeData,
    ) -> VarnodeData;

    /// Naive conversion.
    fn from_ffi(varnode: &ffi::VarnodeData) -> VarnodeData;
}

impl FromFfiVarnode for VarnodeData {
    fn from_ffi_space_ptr_cache(
        spaces_ptr: &mut VecMap<u64, SpaceName>,
        var: &ffi::VarnodeData,
    ) -> VarnodeData {
        let offset = styx_sleigh_bindings::ffi::getVarnodeOffset(var);
        let space_ptr = styx_sleigh_bindings::ffi::getVarnodeSpace(var);
        let space_ref = unsafe { space_ptr.as_ref().unwrap() };
        let space_ptr_value = space_ref as *const _ as u64;

        let cached_space = spaces_ptr.get(&space_ptr_value).cloned();

        let space = cached_space.unwrap_or_else(|| {
            let name_str: &str = space_ref.getName().to_str().unwrap();
            let space_name = SpaceName::from(name_str);

            spaces_ptr.insert(space_ptr_value, space_name.clone());

            space_name
        });

        let size = styx_sleigh_bindings::ffi::getVarnodeSize(var);
        Self {
            space,
            offset,
            size,
        }
    }

    fn from_ffi(var: &ffi::VarnodeData) -> VarnodeData {
        let offset = styx_sleigh_bindings::ffi::getVarnodeOffset(var);
        let space = styx_sleigh_bindings::ffi::getVarnodeSpace(var);
        let space = unsafe { space.as_ref().unwrap() };
        let name: &str = space.getName().to_str().unwrap();

        let space = SpaceName::from(name);

        let size = styx_sleigh_bindings::ffi::getVarnodeSize(var);
        Self {
            space,
            offset,
            size,
        }
    }
}

pub struct PCodeEmitRef<'a> {
    pub space_cached: &'a mut VecMap<u64, SpaceName>,
    pub pcodes: &'a mut Vec<Pcode>,
}

impl<'a> PCodeEmitRef<'a> {
    pub fn new(space_cached: &'a mut VecMap<u64, SpaceName>, pcodes: &'a mut Vec<Pcode>) -> Self {
        Self {
            space_cached,
            pcodes,
        }
    }
}

impl styx_sleigh_bindings::PCodeEmit for PCodeEmitRef<'_> {
    fn dump(
        &mut self,
        _address: &ffi::Address,
        opcode: u32,
        outvar: Option<&ffi::VarnodeData>,
        vars: &CxxVector<ffi::VarnodeData>,
    ) {
        // preallocate for 3 inputs, most instructions won't generate more than this
        let mut inputs = SmallVec::new();
        for v in vars.iter() {
            inputs.push(VarnodeData::from_ffi_space_ptr_cache(self.space_cached, v))
        }

        let output = outvar.map(|x| VarnodeData::from_ffi_space_ptr_cache(self.space_cached, x));
        let opcode = num::FromPrimitive::from_u32(opcode).unwrap();
        let pcode = Pcode {
            opcode,
            inputs,
            output,
        };
        self.pcodes.push(pcode);
    }
}
