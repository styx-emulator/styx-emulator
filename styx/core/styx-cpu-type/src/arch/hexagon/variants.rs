// SPDX-License-Identifier: BSD-2-Clause
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

    pub static ref HEXAGON_REGPAIRS: [CpuRegister; 83] = [
                HexagonRegister::D0.register(),
                HexagonRegister::D1.register(),
                HexagonRegister::D2.register(),
                HexagonRegister::D3.register(),
                HexagonRegister::D4.register(),
                HexagonRegister::D5.register(),
                HexagonRegister::D6.register(),
                HexagonRegister::D7.register(),
                HexagonRegister::D8.register(),
                HexagonRegister::D9.register(),
                HexagonRegister::D10.register(),
                HexagonRegister::D11.register(),
                HexagonRegister::D12.register(),
                HexagonRegister::D13.register(),
                HexagonRegister::D14.register(),
                HexagonRegister::D15.register(),
                HexagonRegister::SGP1SGP0.register(),
                HexagonRegister::S3S2.register(),
                HexagonRegister::S5S4.register(),
                HexagonRegister::S7S6.register(),
                HexagonRegister::S9S8.register(),
                HexagonRegister::S11S10.register(),
                HexagonRegister::S13S12.register(),
                HexagonRegister::S15S14.register(),
                HexagonRegister::S17S16.register(),
                HexagonRegister::S19S18.register(),
                HexagonRegister::S21S20.register(),
                HexagonRegister::S23S22.register(),
                HexagonRegister::S25S24.register(),
                HexagonRegister::S27S26.register(),
                HexagonRegister::S29S28.register(),
                HexagonRegister::S31S30.register(),
                HexagonRegister::S33S32.register(),
                HexagonRegister::S35S34.register(),
                HexagonRegister::S37S36.register(),
                HexagonRegister::S39S38.register(),
                HexagonRegister::S41S40.register(),
                HexagonRegister::S43S42.register(),
                HexagonRegister::S45S44.register(),
                HexagonRegister::S47S46.register(),
                HexagonRegister::S49S48.register(),
                HexagonRegister::S51S50.register(),
                HexagonRegister::S53S52.register(),
                HexagonRegister::S55S54.register(),
                HexagonRegister::S57S56.register(),
                HexagonRegister::S59S58.register(),
                HexagonRegister::S61S60.register(),
                HexagonRegister::S63S62.register(),
                HexagonRegister::S65S64.register(),
                HexagonRegister::S67S66.register(),
                HexagonRegister::S69S68.register(),
                HexagonRegister::S71S70.register(),
                HexagonRegister::S73S72.register(),
                HexagonRegister::S75S74.register(),
                HexagonRegister::S77S76.register(),
                HexagonRegister::S79S78.register(),
                HexagonRegister::G1G0.register(),
                HexagonRegister::G3G2.register(),
                HexagonRegister::G5G4.register(),
                HexagonRegister::G7G6.register(),
                HexagonRegister::G9G8.register(),
                HexagonRegister::G11G10.register(),
                HexagonRegister::G13G12.register(),
                HexagonRegister::G15G14.register(),
                HexagonRegister::G17G16.register(),
                HexagonRegister::G19G18.register(),
                HexagonRegister::G21G20.register(),
                HexagonRegister::G23G22.register(),
                HexagonRegister::G25G24.register(),
                HexagonRegister::G27G26.register(),
                HexagonRegister::G29G28.register(),
                HexagonRegister::G31G30.register(),
                HexagonRegister::C1C0.register(),
                HexagonRegister::C3C2.register(),
                HexagonRegister::C5C4.register(),
                HexagonRegister::C7C6.register(),
                HexagonRegister::C9C8.register(),
                HexagonRegister::C11C10.register(),
                HexagonRegister::Cs.register(),
                HexagonRegister::Upcycle.register(),
                HexagonRegister::C17C16.register(),
                HexagonRegister::PktCount.register(),
                HexagonRegister::Utimer.register(),
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
        regs.extend_from_slice(HEXAGON_REGPAIRS.as_slice());
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
        regs.extend_from_slice(HEXAGON_REGPAIRS.as_slice());
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
