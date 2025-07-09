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
//! Maps the various mips32 architecture variants
use super::gdb_targets::{Mips32CpuTargetDescription, MIPS32_CPU_REGISTER_MAP};
use crate::arch::Mips32Register;
use crate::arch::{Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank};
use derive_more::Display;

#[derive(Default)]
pub struct Mips32GeneralRegisters {}

impl CpuRegisterBank for Mips32GeneralRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Mips32Register::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Mips32Register::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        MIPS32_CPU_REGISTER_MAP.values().cloned().collect()
    }
}

macro_rules! mips32_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone)]
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

            fn insn_word_size(&self) -> usize {
                32
            }

            fn addr_size(&self) -> usize {
                32
            }

            fn architecture(&self) -> Arch {
                Arch::Mips32
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

mips32_arch_impl!(
    Mips32r1Generic,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324kc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324km,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324kp,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324ksc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m4k,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m14kc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m14k,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m14ke,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m14kec,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324kec,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324kem,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324kep,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips324ksd,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kf2_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kf,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kf1_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kfx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kec,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kef2_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kef,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kef1_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kefx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3224kex,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kf2_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kf,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kf1_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kfx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3234kn,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kf2_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kf,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kf1_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kfx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kx,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips3274kf3_2,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips321004kc,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips321004kf2_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips321004kf,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips321004kf1_1,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32interaptiv,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32p5600,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m5100,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);

mips32_arch_impl!(
    Mips32m5101,
    Mips32GeneralRegisters,
    Mips32CpuTargetDescription
);
