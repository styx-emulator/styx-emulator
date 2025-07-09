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
#![allow(unused_imports)]

mod arch;
pub use arch::Arch;

mod arch_endian;
pub use arch_endian::ArchEndian;

mod backend;
pub use backend::Backend;

pub use arch_variant::{ArchVariant, ArmVariant, BlackfinVariant, Ppc32Variant, SuperHVariant};
mod arch_variant;

mod memory_permissions;
pub use memory_permissions::MemoryPermissions;

mod mem_fault_data;
pub use mem_fault_data::MemFaultData;

mod hooks;
pub use hooks::*;

pub(crate) mod processor_core;
pub use processor_core::{HookToken, ProcessorCore};

mod arch_register;
pub use arch_register::{ArmRegister, BlackfinRegister, Ppc32Register, Register, SuperHRegister};

use pyo3::{types::PyModuleMethods, PyResult};
use styx_emulator::core::cpu::arch::{blackfin::BlackfinVariants, ppc32::Ppc32Variants};

use crate::{cpu::mem_fault_data::MemFaultDataType, util::module_system::ModuleSystem};

pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("cpu", |m| {
        m.add_class::<ArchEndian>()?;
        m.add_class::<ProcessorCore>()?;
        m.add_class::<HookToken>()?;
        m.add_class::<Backend>()?;
        m.add_class::<MemoryPermissions>()?;
        m.add_class::<MemFaultData>()?;
        m.add_class::<MemFaultDataType>()?;

        Ok(())
    })?;

    m.register("arch.arm", |m| {
        m.add_class::<ArmVariant>()?;
        m.add_class::<ArmRegister>()?;
        Ok(())
    })?;

    m.register("arch.blackfin", |m| {
        m.add_class::<BlackfinVariant>()?;
        m.add_class::<BlackfinRegister>()?;
        Ok(())
    })?;

    m.register("arch.ppc32", |m| {
        m.add_class::<Ppc32Variant>()?;
        m.add_class::<Ppc32Register>()?;
        Ok(())
    })?;

    m.register("arch.superh", |m| {
        m.add_class::<SuperHVariant>()?;
        m.add_class::<SuperHRegister>()?;
        Ok(())
    })?;

    hooks::register(m)?;

    Ok(())
}
