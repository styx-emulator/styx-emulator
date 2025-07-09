// SPDX-License-Identifier: BSD-2-Clause
//! State management for MTSPR instruction and related logic
use derive_more::Display;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use styx_core::errors::UnknownError;
use styx_core::{
    cpu::arch::ppc32::Ppc32Register,
    hooks::CoreHandle,
    prelude::{CpuBackend, CpuBackendExt},
};
use tracing::{error, info, trace, warn};

use crate::system_interface_unit::SystemInterfaceUnit;

/// Manages the state if the internal effects / status of
/// internal MTSPR SPR's
#[derive(Debug, Default)]
pub struct MtsprStateManager {
    tblw: u32,
    tbuw: u32,
    dec: u32,
}

impl MtsprStateManager {
    pub fn new() -> Self {
        Self {
            tblw: 0,
            tbuw: 0,
            dec: 0,
        }
    }
}

const MTSPR_INSN_MASK: u32 = 0xfc_00_03_ff;
const MTSPR_INSN_BITS: u32 = 0x7c_00_03_a6;
const MTSPR_REG_OPERAND_MASK: u32 = 0x03e0_0000;
const MTSPR_REG_OPERAND_SHIFT: u8 = 21;
const MTSPR_SPR_OPERAND_MASK: u32 = 0x001f_f800;
const MTSPR_SPR_OPERAND_SHIFT: u8 = 11;

#[inline]
fn is_mtspr(b: u32) -> bool {
    // 0x7c 00 03 a6
    // & OP=31, where OP == (26,31)
    // & SPRVAL
    // & S
    // & XOP_1_10=467
    // & BIT_0=0
    b & MTSPR_INSN_MASK == MTSPR_INSN_BITS
}

#[allow(non_snake_case)]
const fn FLIP_SPR(bits: u16) -> u16 {
    let lower = bits & 0x1fu16;
    let upper = (bits & 0x3e0u16) >> 5;

    (lower << 5) | upper
}
/// This is flipped across a word boundary,
/// so instead of being 10 contiguous bits,
/// the representation of the enum flips around the
/// middle 5th bit, so we have to use the [`FLIP_SPR`]
/// `const fn` as a conversion from the const enum human-consumable
/// repr into the actual machine representation
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(
    Debug, Display, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, ToPrimitive, FromPrimitive,
)]
pub enum SprEnum {
    XER = FLIP_SPR(1),
    LR = FLIP_SPR(8),
    CTR = FLIP_SPR(9),
    DSISR = FLIP_SPR(18),
    DAR = FLIP_SPR(19),
    DEC = FLIP_SPR(22),
    SDR1 = FLIP_SPR(25),
    SRR0 = FLIP_SPR(26),
    SRR1 = FLIP_SPR(27),
    CSRR0 = FLIP_SPR(58),
    CSRR1 = FLIP_SPR(59),
    EIE = FLIP_SPR(80),
    EID = FLIP_SPR(81),
    NRI = FLIP_SPR(82),
    SPRG0 = FLIP_SPR(272),
    SPRG1 = FLIP_SPR(273),
    SPRG2 = FLIP_SPR(274),
    SPRG3 = FLIP_SPR(275),
    EAR = FLIP_SPR(282),
    TBLr = FLIP_SPR(268),
    TBUr = FLIP_SPR(269),
    TBLw = FLIP_SPR(284),
    TBUw = FLIP_SPR(285),
    PVR = FLIP_SPR(287),
    IBAT0U = FLIP_SPR(528),
    IBAT0L = FLIP_SPR(529),
    IBAT1U = FLIP_SPR(530),
    IBAT1L = FLIP_SPR(531),
    IBAT2U = FLIP_SPR(532),
    IBAT2L = FLIP_SPR(533),
    IBAT3U = FLIP_SPR(534),
    IBAT3L = FLIP_SPR(535),
    DBAT0U = FLIP_SPR(536),
    DBAT0L = FLIP_SPR(537),
    DBAT1U = FLIP_SPR(538),
    DBAT1L = FLIP_SPR(539),
    DBAT2U = FLIP_SPR(540),
    DBAT2L = FLIP_SPR(541),
    DBAT3U = FLIP_SPR(542),
    DBAT3L = FLIP_SPR(543),
    MQ = FLIP_SPR(0),
    RTCU = FLIP_SPR(20),
    RTCL = FLIP_SPR(21),
    IMMR = FLIP_SPR(638),
    IC_CST = FLIP_SPR(560),
    IC_ADR = FLIP_SPR(561),
    IC_DAT = FLIP_SPR(562),
    DC_CST = FLIP_SPR(568),
    DC_ADR = FLIP_SPR(596),
    DC_DAT = FLIP_SPR(570),
    MI_CTR = FLIP_SPR(784),
    MI_AP = FLIP_SPR(786),
    MI_EPN = FLIP_SPR(787),
    MI_TWC = FLIP_SPR(789),
    MI_RPN = FLIP_SPR(790),
    MI_CAM = FLIP_SPR(816),
    MI_RAM0 = FLIP_SPR(817),
    MI_RAM1 = FLIP_SPR(818),
    MD_CTR = FLIP_SPR(792),
    M_CASID = FLIP_SPR(793),
    MD_AP = FLIP_SPR(794),
    MD_EPN = FLIP_SPR(795),
    M_TWB = FLIP_SPR(796),
    MD_TWC = FLIP_SPR(797),
    MD_RPN = FLIP_SPR(798),
    M_TW = FLIP_SPR(799),
    MD_CAM = FLIP_SPR(824),
    MD_RAM0 = FLIP_SPR(825),
    MD_RAM1 = FLIP_SPR(826),
    // debug level sprs
    CMPA = FLIP_SPR(144),
    CMPB = FLIP_SPR(145),
    CMPC = FLIP_SPR(146),
    CMPD = FLIP_SPR(147),
    ICR = FLIP_SPR(148),
    DER = FLIP_SPR(149),
    COUNTA = FLIP_SPR(150),
    COUNTB = FLIP_SPR(151),
    CMPE = FLIP_SPR(152),
    CMPF = FLIP_SPR(153),
    CMPG = FLIP_SPR(154),
    CMPH = FLIP_SPR(155),
    LCTRL1 = FLIP_SPR(156),
    LCTRL2 = FLIP_SPR(157),
    ICTRL = FLIP_SPR(158),
    BAR = FLIP_SPR(159),
    DPDR = FLIP_SPR(630),
}

#[allow(dead_code)] // enum repeats
impl SprEnum {
    const MI_L1DL2P: Self = Self::MI_TWC;
    const MD_L1P: Self = Self::M_TWB;
    const MD_L1DL2P: Self = Self::MD_TWC;
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MtsprInstruction {
    register: Ppc32Register,
    spr: SprEnum,
    value: u32,
}

impl MtsprInstruction {
    pub fn new(data: u32, cpu: &mut dyn CpuBackend) -> Option<Self> {
        if is_mtspr(data) {
            let register = Self::parse_register(data).unwrap();
            let value = cpu.read_register::<u32>(register).unwrap();
            let spr = Self::parse_spr(data).unwrap();

            Some(Self {
                register,
                spr,
                value,
            })
        } else {
            None
        }
    }

    /// This method assumes that the data has already been validated as
    /// being an MTSPR instruction
    #[inline]
    pub fn parse_register(data: u32) -> Option<Ppc32Register> {
        let operand: u8 = ((data & MTSPR_REG_OPERAND_MASK) >> MTSPR_REG_OPERAND_SHIFT)
            .try_into()
            .unwrap();

        match operand {
            0 => Some(Ppc32Register::R0),
            1 => Some(Ppc32Register::R1),
            2 => Some(Ppc32Register::R2),
            3 => Some(Ppc32Register::R3),
            4 => Some(Ppc32Register::R4),
            5 => Some(Ppc32Register::R5),
            6 => Some(Ppc32Register::R6),
            7 => Some(Ppc32Register::R7),
            8 => Some(Ppc32Register::R8),
            9 => Some(Ppc32Register::R9),
            10 => Some(Ppc32Register::R10),
            11 => Some(Ppc32Register::R11),
            12 => Some(Ppc32Register::R12),
            13 => Some(Ppc32Register::R13),
            14 => Some(Ppc32Register::R14),
            15 => Some(Ppc32Register::R15),
            16 => Some(Ppc32Register::R16),
            17 => Some(Ppc32Register::R17),
            18 => Some(Ppc32Register::R18),
            19 => Some(Ppc32Register::R19),
            20 => Some(Ppc32Register::R20),
            21 => Some(Ppc32Register::R21),
            22 => Some(Ppc32Register::R22),
            23 => Some(Ppc32Register::R23),
            24 => Some(Ppc32Register::R24),
            25 => Some(Ppc32Register::R25),
            26 => Some(Ppc32Register::R26),
            27 => Some(Ppc32Register::R27),
            28 => Some(Ppc32Register::R28),
            29 => Some(Ppc32Register::R29),
            30 => Some(Ppc32Register::R30),
            31 => Some(Ppc32Register::R31),
            _ => None,
        }
    }

    /// This method assumes that the data has already been validated as
    /// being an MTSPR instruction
    #[inline]
    pub fn parse_spr(data: u32) -> Option<SprEnum> {
        let data = (data & MTSPR_SPR_OPERAND_MASK) >> MTSPR_SPR_OPERAND_SHIFT;
        FromPrimitive::from_u32(data)
    }
}

/// Many SPR values are unsupported in various backends,
/// so ad utility to skip instructions sometimes as we
/// emulate them above the backend level
fn skip_cpu_insn(cpu: &mut dyn CpuBackend) {
    let next_pc = cpu.pc().unwrap() + 4;
    cpu.set_pc(next_pc).unwrap();
}

pub(crate) fn mtspr_proxy(proc: CoreHandle) -> Result<(), UnknownError> {
    let pc = proc.cpu.pc().unwrap();

    // get insn @ pc
    let insn_bytes = proc.mmu.read_u32_be_phys_code(pc).unwrap();

    // check if insn is mtspr
    if is_mtspr(insn_bytes) {
        let siu = proc
            .event_controller
            .peripherals
            .get::<SystemInterfaceUnit>()
            .unwrap();

        let mtspr = MtsprInstruction::new(insn_bytes, proc.cpu).unwrap();
        trace!("MTSPR @ {:#x}: `{:?}`", pc, mtspr);
        match mtspr.spr {
            SprEnum::TBLw => {
                trace!("executing {:?} impl", mtspr);
                siu.mtspr_mgr.tblw = mtspr.value;
                skip_cpu_insn(proc.cpu);
            }
            SprEnum::TBUw => {
                trace!("executing {:?} impl", mtspr);
                siu.mtspr_mgr.tbuw = mtspr.value;
                skip_cpu_insn(proc.cpu);
            }
            SprEnum::DEC => {
                trace!("executing {:?} impl", mtspr);
                error!("DEC = {:#x}", mtspr.value);
                siu.mtspr_mgr.dec = mtspr.value;
                skip_cpu_insn(proc.cpu);
            }
            SprEnum::CTR | SprEnum::LR => {
                trace!("Backend executing {:?}", mtspr);
            }
            SprEnum::IMMR => {
                info!("mtspr IMMR, relocating to {:#x}", mtspr.value);
                siu.set_immr_hooks(proc.cpu, mtspr.value as u64).unwrap();
            }
            not_handled => {
                // nothing to do for this variant
                warn!(
                    "unhandled mtspr: {} @ pc: {:#08x}",
                    not_handled,
                    proc.cpu.pc().unwrap(),
                );
            }
        }
    }

    Ok(())
}
