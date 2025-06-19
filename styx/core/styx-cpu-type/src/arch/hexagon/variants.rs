// BSD 2-Clause License
//
// Copyright (c) 2025, Styx Emulator Project
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
//! Maps the various hexagon architecture variants

use super::{
    gdb_targets::{
        HexagonCpuTargetDescription, HEXAGON_CORE_CPU_REGISTER_MAP,
        HEXAGON_CORE_HVX_CPU_REGISTER_MAP,
    },
    HexagonRegister,
};
use crate::arch::{Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank};
use derive_more::Display;

// TODO: macroize?
#[derive(Default)]
pub struct HexagonGeneralRegisters {}

impl CpuRegisterBank for HexagonGeneralRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        HexagonRegister::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        HexagonRegister::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        HEXAGON_CORE_CPU_REGISTER_MAP.values().cloned().collect()
    }
}

#[derive(Default)]
pub struct HexagonGeneralRegistersWithHvx {}

impl CpuRegisterBank for HexagonGeneralRegistersWithHvx {
    fn pc(&self) -> crate::arch::CpuRegister {
        HexagonRegister::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        HexagonRegister::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        HEXAGON_CORE_HVX_CPU_REGISTER_MAP
            .values()
            .cloned()
            .collect()
    }
}

macro_rules! hexagon_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                32
            }

            fn pc_size(&self) -> usize {
                32
            }

            fn core_register_size(&self) -> usize {
                32
            }

            fn data_word_size(&self) -> usize {
                32
            }

            // Hexagon instructions technically can be grouped into blocks called "packets,"
            // thanks to its being a VLIW architecture. So technically, while every instruction
            // is 32 bits, you can have an packet of up to four instructions executed in parallel.
            fn insn_word_size(&self) -> usize {
                32
            }

            fn addr_size(&self) -> usize {
                32
            }

            fn architecture(&self) -> Arch {
                Arch::Hexagon
            }

            fn architecture_variant(&self) -> String {
                format!("{}", self)
            }

            fn registers(&self) -> Box<dyn CpuRegisterBank> {
                Box::<$registers_struct>::default()
            }

            fn gdb_target_description(&self) -> crate::arch::GdbTargetDescriptionImpl {
                <$target_description>::default().into()
            }
        }
    };
}

// TODO: change to HexagonGeneralRegistersWithHvx? Need to find out which DSPs have HVX and which don't.
macro_rules! hexagon_arch_impls (
    ($($variant_name:ident),*) => {
        $(hexagon_arch_impl!(
            $variant_name,
            HexagonGeneralRegisters,
            HexagonCpuTargetDescription
        );
    )*
    };
);

// Found from https://github.com/n-o-o-n/idp_hexagon
// QDSP6V67T is "Hexagon V67 Small Core."
hexagon_arch_impls!(
    QDSP6V4, QDSP6V5, QDSP6V55, QDSP6V60, QDSPV61, QDSP6V62, QDSP6V65, QDSP6V66, QDSP6V67,
    QDSP6V67T, QDSP6V69, QDSP6V71, QDSP6V73, QDSP6V77, QDPS6V79
);
