use std::collections::HashMap;

use log::trace;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use styx_cpu_type::arch::{
    backends::{ArchRegister, BasicArchRegister},
    hexagon::HexagonRegister,
};
use styx_errors::anyhow::anyhow;
use styx_processor::cpu::backend::ReadRegisterError;
use styx_processor::cpu::CpuBackendExt;
use styx_sync::lazy_static;

use crate::{
    arch_spec::ArchSpecBuilder,
    memory::sized_value::SizedValue,
    register_manager::{RegisterCallback, RegisterHandleError, RegisterManager},
    PcodeBackend,
};

// TODO: FxHashmap here?
lazy_static! {
    pub static ref REGPAIR_MAP: HashMap<HexagonRegister, (HexagonRegister, HexagonRegister)> =
        HashMap::from([
            (
                HexagonRegister::D0,
                (HexagonRegister::R1, HexagonRegister::R0)
            ),
            (
                HexagonRegister::D1,
                (HexagonRegister::R3, HexagonRegister::R2)
            ),
            (
                HexagonRegister::D2,
                (HexagonRegister::R5, HexagonRegister::R4)
            ),
            (
                HexagonRegister::D3,
                (HexagonRegister::R7, HexagonRegister::R6)
            ),
            (
                HexagonRegister::D4,
                (HexagonRegister::R9, HexagonRegister::R8)
            ),
            (
                HexagonRegister::D5,
                (HexagonRegister::R11, HexagonRegister::R10)
            ),
            (
                HexagonRegister::D6,
                (HexagonRegister::R13, HexagonRegister::R12)
            ),
            (
                HexagonRegister::D7,
                (HexagonRegister::R15, HexagonRegister::R14)
            ),
            (
                HexagonRegister::D8,
                (HexagonRegister::R17, HexagonRegister::R16)
            ),
            (
                HexagonRegister::D9,
                (HexagonRegister::R19, HexagonRegister::R18)
            ),
            (
                HexagonRegister::D10,
                (HexagonRegister::R21, HexagonRegister::R20)
            ),
            (
                HexagonRegister::D11,
                (HexagonRegister::R23, HexagonRegister::R22)
            ),
            (
                HexagonRegister::D12,
                (HexagonRegister::R25, HexagonRegister::R24)
            ),
            (
                HexagonRegister::D13,
                (HexagonRegister::R27, HexagonRegister::R26)
            ),
            (
                HexagonRegister::D14,
                (HexagonRegister::Sp, HexagonRegister::R28)
            ),
            (
                HexagonRegister::D15,
                (HexagonRegister::Lr, HexagonRegister::Fp)
            ),
            (
                HexagonRegister::SGP1SGP0,
                (HexagonRegister::Sgp1, HexagonRegister::Sgp0)
            ),
            (
                HexagonRegister::S3S2,
                (HexagonRegister::Elr, HexagonRegister::Stid)
            ),
            (
                HexagonRegister::S5S4,
                (HexagonRegister::BadVa1, HexagonRegister::BadVa0)
            ),
            (
                HexagonRegister::S7S6,
                (HexagonRegister::Ccr, HexagonRegister::Ssr)
            ),
            (
                HexagonRegister::S9S8,
                (HexagonRegister::BadVa, HexagonRegister::Htid)
            ),
            (
                HexagonRegister::S11S10,
                (HexagonRegister::S11, HexagonRegister::Imask)
            ),
            (
                HexagonRegister::S13S12,
                (HexagonRegister::S13, HexagonRegister::S12)
            ),
            (
                HexagonRegister::S15S14,
                (HexagonRegister::S15, HexagonRegister::S14)
            ),
            (
                HexagonRegister::S17S16,
                (HexagonRegister::ModeCtl, HexagonRegister::Evb)
            ),
            (
                HexagonRegister::S19S18,
                (HexagonRegister::S19, HexagonRegister::SysCfg)
            ),
            (
                HexagonRegister::S21S20,
                (HexagonRegister::Vid, HexagonRegister::S20)
            ),
            (
                HexagonRegister::S23S22,
                (HexagonRegister::S23, HexagonRegister::S22)
            ),
            (
                HexagonRegister::S25S24,
                (HexagonRegister::S25, HexagonRegister::S24)
            ),
            (
                HexagonRegister::S27S26,
                (HexagonRegister::CfgBase, HexagonRegister::S26)
            ),
            (
                HexagonRegister::S29S28,
                (HexagonRegister::Rev, HexagonRegister::Diag)
            ),
            (
                HexagonRegister::S31S30,
                (HexagonRegister::PcycleHi, HexagonRegister::PcycleLo)
            ),
            (
                HexagonRegister::S33S32,
                (HexagonRegister::IsdbCfg0, HexagonRegister::IsdbSt)
            ),
            (
                HexagonRegister::S35S34,
                (HexagonRegister::S35, HexagonRegister::IsdbCfg1)
            ),
            (
                HexagonRegister::S37S36,
                (HexagonRegister::BrkptCfg0, HexagonRegister::BrkptPc0)
            ),
            (
                HexagonRegister::S39S38,
                (HexagonRegister::BrkptCfg1, HexagonRegister::BrkptPc1)
            ),
            (
                HexagonRegister::S41S40,
                (HexagonRegister::IsdbMbxOut, HexagonRegister::IsdbMbxIn)
            ),
            (
                HexagonRegister::S43S42,
                (HexagonRegister::IsdbGpr, HexagonRegister::IsdbEn)
            ),
            (
                HexagonRegister::S45S44,
                (HexagonRegister::S45, HexagonRegister::S44)
            ),
            (
                HexagonRegister::S47S46,
                (HexagonRegister::S47, HexagonRegister::S46)
            ),
            (
                HexagonRegister::S49S48,
                (HexagonRegister::PmuCnt1, HexagonRegister::PmuCnt0)
            ),
            (
                HexagonRegister::S51S50,
                (HexagonRegister::PmuCnt3, HexagonRegister::PmuCnt2)
            ),
            (
                HexagonRegister::S53S52,
                (HexagonRegister::PmuCfg, HexagonRegister::PmuEvtCfg)
            ),
            (
                HexagonRegister::S55S54,
                (HexagonRegister::S55, HexagonRegister::S54)
            ),
            (
                HexagonRegister::S57S56,
                (HexagonRegister::S57, HexagonRegister::S56)
            ),
            (
                HexagonRegister::S59S58,
                (HexagonRegister::S59, HexagonRegister::S58)
            ),
            (
                HexagonRegister::S61S60,
                (HexagonRegister::S61, HexagonRegister::S60)
            ),
            (
                HexagonRegister::S63S62,
                (HexagonRegister::S63, HexagonRegister::S62)
            ),
            (
                HexagonRegister::S65S64,
                (HexagonRegister::S65, HexagonRegister::S64)
            ),
            (
                HexagonRegister::S67S66,
                (HexagonRegister::S67, HexagonRegister::S66)
            ),
            (
                HexagonRegister::S69S68,
                (HexagonRegister::S69, HexagonRegister::S68)
            ),
            (
                HexagonRegister::S71S70,
                (HexagonRegister::S71, HexagonRegister::S70)
            ),
            (
                HexagonRegister::S73S72,
                (HexagonRegister::S73, HexagonRegister::S72)
            ),
            (
                HexagonRegister::S75S74,
                (HexagonRegister::S75, HexagonRegister::S74)
            ),
            (
                HexagonRegister::S77S76,
                (HexagonRegister::S77, HexagonRegister::S76)
            ),
            (
                HexagonRegister::S79S78,
                (HexagonRegister::S79, HexagonRegister::S78)
            ),
            (
                HexagonRegister::G1G0,
                (HexagonRegister::Gsr, HexagonRegister::Gelr)
            ),
            (
                HexagonRegister::G3G2,
                (HexagonRegister::G3, HexagonRegister::Gosp)
            ),
            (
                HexagonRegister::G5G4,
                (HexagonRegister::G5, HexagonRegister::G4)
            ),
            (
                HexagonRegister::G7G6,
                (HexagonRegister::G7, HexagonRegister::G6)
            ),
            (
                HexagonRegister::G9G8,
                (HexagonRegister::G9, HexagonRegister::G8)
            ),
            (
                HexagonRegister::G11G10,
                (HexagonRegister::G11, HexagonRegister::G10)
            ),
            (
                HexagonRegister::G13G12,
                (HexagonRegister::G13, HexagonRegister::G12)
            ),
            (
                HexagonRegister::G15G14,
                (HexagonRegister::G15, HexagonRegister::G14)
            ),
            (
                HexagonRegister::G17G16,
                (HexagonRegister::Gpmucnt5, HexagonRegister::Gpmucnt4)
            ),
            (
                HexagonRegister::G19G18,
                (HexagonRegister::Gpmucnt7, HexagonRegister::Gpmucnt6)
            ),
            (
                HexagonRegister::G21G20,
                (HexagonRegister::G21, HexagonRegister::G20)
            ),
            (
                HexagonRegister::G23G22,
                (HexagonRegister::G23, HexagonRegister::G22)
            ),
            (
                HexagonRegister::G25G24,
                (HexagonRegister::Gpcyclehi, HexagonRegister::Gpcyclelo)
            ),
            (
                HexagonRegister::G27G26,
                (HexagonRegister::Gpmucnt1, HexagonRegister::Gpmucnt0)
            ),
            (
                HexagonRegister::G29G28,
                (HexagonRegister::Gpmucnt3, HexagonRegister::Gpmucnt2)
            ),
            (
                HexagonRegister::G31G30,
                (HexagonRegister::G31, HexagonRegister::G30)
            ),
            (
                HexagonRegister::C1C0,
                (HexagonRegister::Lc0, HexagonRegister::Sa0)
            ),
            (
                HexagonRegister::C3C2,
                (HexagonRegister::Lc1, HexagonRegister::Sa1)
            ),
            (
                HexagonRegister::C5C4,
                (HexagonRegister::C5, HexagonRegister::P3_0)
            ),
            (
                HexagonRegister::C7C6,
                (HexagonRegister::M1, HexagonRegister::M0)
            ),
            (
                HexagonRegister::C9C8,
                (HexagonRegister::Pc, HexagonRegister::Usr)
            ),
            (
                HexagonRegister::C11C10,
                (HexagonRegister::Gp, HexagonRegister::Ugp)
            ),
            // C13C12
            (
                HexagonRegister::Cs,
                (HexagonRegister::Cs1, HexagonRegister::Cs0)
            ),
            // C15C14
            (
                HexagonRegister::Upcycle,
                (HexagonRegister::UpcycleHi, HexagonRegister::UpcycleLo)
            ),
            (
                HexagonRegister::C17C16,
                (HexagonRegister::FrameKey, HexagonRegister::FrameLimit)
            ),
            (
                HexagonRegister::PktCount,
                (HexagonRegister::PktCountHi, HexagonRegister::PktCountHi)
            ),
            (
                HexagonRegister::Utimer,
                (HexagonRegister::UtimerHi, HexagonRegister::UtimerLo)
            )
        ]);
}

impl RegpairHandler {
    fn get_pairs_from_archregister(
        register: ArchRegister,
    ) -> Option<(HexagonRegister, HexagonRegister)> {
        // WARN: this assumes the registers are defined contiguously
        match register {
            ArchRegister::Basic(BasicArchRegister::Hexagon(reg)) => {
                return REGPAIR_MAP.get(&reg).copied();
            }
            _ => unreachable!(),
        }
    }

    fn get_pair(
        target: HexagonRegister,
        start: HexagonRegister,
        end: HexagonRegister,
        start_map: HexagonRegister,
    ) -> Option<(HexagonRegister, HexagonRegister)> {
        let target_val = target.to_u32()?;
        let start_val = start.to_u32()?;
        let start_map_val = start_map.to_u32()?;
        let end_val = end.to_u32()?;

        if target_val >= start_val && target_val <= end_val {
            let offset = target_val - start_val;

            let reg_lo = HexagonRegister::from_u32(start_map_val + (offset * 2))?;
            let reg_hi = HexagonRegister::from_u32(start_map_val + (offset * 2) + 1)?;

            Some((reg_lo, reg_hi))
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct RegpairHandler;
impl RegisterCallback for RegpairHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut PcodeBackend,
    ) -> Result<SizedValue, RegisterHandleError> {
        let (reg_lo, reg_hi) = Self::get_pairs_from_archregister(register)
            .ok_or(anyhow!("could not get registers to read from"))?;

        // Don't read more than we should be; then zero-extend the values
        let lo = cpu
            .read_register::<u32>(reg_lo)
            .map_err(|e| RegisterHandleError::Other(e.into()))? as u64;
        let hi = cpu
            .read_register::<u32>(reg_hi)
            .map_err(|e| RegisterHandleError::Other(e.into()))? as u64;

        let combined = (hi << 32) | lo;

        trace!(
            "regpair read_pair: reg_lo {} lo {} reg_hi {} hi {} combined {}",
            reg_lo,
            lo,
            reg_hi,
            hi,
            combined
        );

        Ok(combined.into())
    }

    fn write(
        &mut self,
        register: ArchRegister,
        write_val: SizedValue,
        cpu: &mut PcodeBackend,
    ) -> Result<(), RegisterHandleError> {
        // must be 64 bit for this handler
        assert_eq!(write_val.size(), 8);

        let (reg_lo, reg_hi) = Self::get_pairs_from_archregister(register)
            .ok_or(anyhow!("could not get registers to write from"))?;

        let write_val = write_val
            .to_u64()
            .ok_or(RegisterHandleError::Other(anyhow!(
                "could not get 64 bit value to write to register pair"
            )))?;

        let lo = (write_val & 0xffffffff) as u32;
        let hi = ((write_val >> 32) & 0xffffffff) as u32;

        trace!("regpair write_pair: lo {} hi {}", lo, hi);

        cpu.write_register(reg_lo, lo)
            .map_err(|e| RegisterHandleError::Other(e.into()))?;
        cpu.write_register(reg_hi, hi)
            .map_err(|e| RegisterHandleError::Other(e.into()))?;

        Ok(())
    }
}

// TODO: vector register pairs

pub fn add_register_pair_handlers<S>(spec: &mut ArchSpecBuilder<S>) {
    let register_manager = &mut spec.register_manager;
    for reg in REGPAIR_MAP.keys() {
        trace!("adding regpair handler for {}", reg);
        register_manager
            .add_handler(*reg, RegpairHandler)
            .expect("couldn't add regpair handler");
    }
}
