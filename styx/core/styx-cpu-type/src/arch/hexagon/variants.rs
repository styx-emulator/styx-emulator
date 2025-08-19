// SPDX-License-Identifier: BSD-2-Clause
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
// BSD 2-Clause License
//! Maps the various hexagon architecture variants
use super::{
    gdb_targets::{
        HexagonCpuTargetDescription, HEXAGON_CORE_CPU_REGISTER_MAP,
        HEXAGON_CORE_HVX_CPU_REGISTER_MAP,
    },
    HexagonRegister,
};
use crate::arch::{Arch, ArchitectureDef, ArchitectureVariant, CpuRegister, CpuRegisterBank};
use derive_more::Display;
use styx_sync::lazy_static;

lazy_static! {
    pub static ref HEXAGON_SYSTEM_GUEST_REGS: [CpuRegister; 113] = [
        HexagonRegister::Sgp0.register(),
        HexagonRegister::Sgp1.register(),
        HexagonRegister::Stid.register(),
        HexagonRegister::Elr.register(),
        HexagonRegister::BadVa0.register(),
        HexagonRegister::BadVa1.register(),
        HexagonRegister::Ssr.register(),
        HexagonRegister::Ccr.register(),
        HexagonRegister::Htid.register(),
        HexagonRegister::BadVa.register(),
        HexagonRegister::Imask.register(),
        HexagonRegister::S11.register(),
        HexagonRegister::S12.register(),
        HexagonRegister::S13.register(),
        HexagonRegister::S14.register(),
        HexagonRegister::S15.register(),
        HexagonRegister::Evb.register(),
        HexagonRegister::ModeCtl.register(),
        HexagonRegister::SysCfg.register(),
        HexagonRegister::S19.register(),
        HexagonRegister::S20.register(),
        HexagonRegister::Vid.register(),
        HexagonRegister::S22.register(),
        HexagonRegister::S23.register(),
        HexagonRegister::S24.register(),
        HexagonRegister::S25.register(),
        HexagonRegister::S26.register(),
        HexagonRegister::CfgBase.register(),
        HexagonRegister::Diag.register(),
        HexagonRegister::Rev.register(),
        HexagonRegister::PcycleLo.register(),
        HexagonRegister::PcycleHi.register(),
        HexagonRegister::IsdbSt.register(),
        HexagonRegister::IsdbCfg0.register(),
        HexagonRegister::IsdbCfg1.register(),
        HexagonRegister::S35.register(),
        HexagonRegister::BrkptPc0.register(),
        HexagonRegister::BrkptCfg0.register(),
        HexagonRegister::BrkptPc1.register(),
        HexagonRegister::BrkptCfg1.register(),
        HexagonRegister::IsdbMbxIn.register(),
        HexagonRegister::IsdbMbxOut.register(),
        HexagonRegister::IsdbEn.register(),
        HexagonRegister::IsdbGpr.register(),
        HexagonRegister::S44.register(),
        HexagonRegister::S45.register(),
        HexagonRegister::S46.register(),
        HexagonRegister::S47.register(),
        HexagonRegister::PmuCnt0.register(),
        HexagonRegister::PmuCnt1.register(),
        HexagonRegister::PmuCnt2.register(),
        HexagonRegister::PmuCnt3.register(),
        HexagonRegister::PmuEvtCfg.register(),
        HexagonRegister::PmuCfg.register(),
        HexagonRegister::S54.register(),
        HexagonRegister::S55.register(),
        HexagonRegister::S56.register(),
        HexagonRegister::S57.register(),
        HexagonRegister::S58.register(),
        HexagonRegister::S59.register(),
        HexagonRegister::S60.register(),
        HexagonRegister::S61.register(),
        HexagonRegister::S62.register(),
        HexagonRegister::S63.register(),
        HexagonRegister::S64.register(),
        HexagonRegister::S65.register(),
        HexagonRegister::S66.register(),
        HexagonRegister::S67.register(),
        HexagonRegister::S68.register(),
        HexagonRegister::S69.register(),
        HexagonRegister::S70.register(),
        HexagonRegister::S71.register(),
        HexagonRegister::S72.register(),
        HexagonRegister::S73.register(),
        HexagonRegister::S74.register(),
        HexagonRegister::S75.register(),
        HexagonRegister::S76.register(),
        HexagonRegister::S77.register(),
        HexagonRegister::S78.register(),
        HexagonRegister::S79.register(),
        HexagonRegister::S80.register(),
        // Guest registers
        HexagonRegister::Gelr.register(),
        HexagonRegister::Gsr.register(),
        HexagonRegister::Gosp.register(),
        HexagonRegister::G3.register(),
        HexagonRegister::G4.register(),
        HexagonRegister::G5.register(),
        HexagonRegister::G6.register(),
        HexagonRegister::G7.register(),
        HexagonRegister::G8.register(),
        HexagonRegister::G9.register(),
        HexagonRegister::G10.register(),
        HexagonRegister::G11.register(),
        HexagonRegister::G12.register(),
        HexagonRegister::G13.register(),
        HexagonRegister::G14.register(),
        HexagonRegister::G15.register(),
        HexagonRegister::Gpmucnt4.register(),
        HexagonRegister::Gpmucnt5.register(),
        HexagonRegister::Gpmucnt6.register(),
        HexagonRegister::Gpmucnt7.register(),
        HexagonRegister::G20.register(),
        HexagonRegister::G21.register(),
        HexagonRegister::G22.register(),
        HexagonRegister::G23.register(),
        HexagonRegister::Gpcyclelo.register(),
        HexagonRegister::Gpcyclehi.register(),
        HexagonRegister::Gpmucnt0.register(),
        HexagonRegister::Gpmucnt1.register(),
        HexagonRegister::Gpmucnt2.register(),
        HexagonRegister::Gpmucnt3.register(),
        HexagonRegister::G30.register(),
        HexagonRegister::G31.register(),
    ];

    pub static ref HEXAGON_PREDICATES: [CpuRegister; 8] = [
        HexagonRegister::P0.register(),
        HexagonRegister::P1.register(),
        HexagonRegister::P2.register(),
        HexagonRegister::P3.register(),
        HexagonRegister::DestP0.register(),
        HexagonRegister::DestP1.register(),
        HexagonRegister::DestP2.register(),
        HexagonRegister::DestP3.register(),
    ];

}

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
        let mut regs = HEXAGON_CORE_CPU_REGISTER_MAP
            .values()
            .cloned()
            .collect::<Vec<_>>();
        regs.extend_from_slice(HEXAGON_SYSTEM_GUEST_REGS.as_slice());
        regs.extend_from_slice(HEXAGON_PREDICATES.as_slice());
        regs
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
        // This needs to be concatenated with
        // the system and guest registers
        let mut regs = HEXAGON_CORE_HVX_CPU_REGISTER_MAP
            .values()
            .cloned()
            .collect::<Vec<_>>();
        regs.extend_from_slice(HEXAGON_SYSTEM_GUEST_REGS.as_slice());
        regs.extend_from_slice(HEXAGON_PREDICATES.as_slice());
        regs
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
