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
    memory::sized_value::SizedValue,
    register_manager::{RegisterCallback, RegisterHandleError},
    PcodeBackend,
};
use styx_cpu_type::arch::backends::ArchRegister;

#[derive(Debug, Default)]
pub struct FloatingPointExtensionHandler {
    value: u64,
}

impl RegisterCallback for FloatingPointExtensionHandler {
    fn read(
        &mut self,
        _register: ArchRegister,
        _backend: &mut PcodeBackend,
    ) -> Result<SizedValue, RegisterHandleError> {
        Ok(SizedValue::from_u64(self.value, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        _backend: &mut PcodeBackend,
    ) -> Result<(), RegisterHandleError> {
        self.value = value.to_u64().unwrap();

        Ok(())
    }
}
