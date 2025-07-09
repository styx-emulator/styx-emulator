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
use crate::arch::{
    Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank, GdbTargetDescriptionImpl,
};
use derive_more::Display;

use super::gdb_targets::{Aarch64CoreDescription, AARCH64_CORE_REGISTER_MAP};
use super::Aarch64Register;

/// A "sane-default" set of default ARM registers.
#[derive(Default)]
pub struct Aarch64CoreRegisters {}

impl CpuRegisterBank for Aarch64CoreRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Aarch64Register::PC.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Aarch64Register::SP.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        AARCH64_CORE_REGISTER_MAP.values().cloned().collect()
    }
}

macro_rules! aarch64_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                64
            }

            fn pc_size(&self) -> usize {
                64
            }

            fn core_register_size(&self) -> usize {
                64
            }

            fn data_word_size(&self) -> usize {
                64
            }

            fn insn_word_size(&self) -> usize {
                64
            }

            fn addr_size(&self) -> usize {
                64
            }

            fn architecture(&self) -> Arch {
                Arch::Aarch64
            }

            fn architecture_variant(&self) -> String {
                format!("{}", self)
            }

            fn registers(&self) -> Box<dyn CpuRegisterBank> {
                Box::<$registers_struct>::default()
            }

            fn gdb_target_description(&self) -> GdbTargetDescriptionImpl {
                <$target_description>::default().into()
            }
        }
    };
}

aarch64_arch_impl!(Generic, Aarch64CoreRegisters, Aarch64CoreDescription);
