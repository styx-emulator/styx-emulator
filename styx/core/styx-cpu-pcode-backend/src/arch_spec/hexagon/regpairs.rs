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
use std::collections::HashMap;

use log::{debug, trace};
use styx_cpu_type::arch::{
    backends::{ArchRegister, BasicArchRegister},
    hexagon::HexagonRegister,
};
use styx_errors::anyhow::anyhow;
use styx_processor::cpu::{CpuBackend, CpuBackendExt};
use styx_sync::lazy_static;

use crate::register_manager::RegisterCallbackCpu;
use crate::{
    arch_spec::ArchSpecBuilder,
    memory::sized_value::SizedValue,
    register_manager::{RegisterCallback, RegisterHandleError},
};

use super::backend::HexagonPcodeBackend;

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
                (HexagonRegister::PktCountHi, HexagonRegister::PktCountLo)
            ),
            (
                HexagonRegister::Utimer,
                (HexagonRegister::UtimerHi, HexagonRegister::UtimerLo)
            )
        ]);

    pub static ref VECTOR_REGPAIR_MAP: HashMap<HexagonRegister, (HexagonRegister, HexagonRegister)> =
        HashMap::from([
            (HexagonRegister::W0, (HexagonRegister::V1, HexagonRegister::V0)),
            (HexagonRegister::W1, (HexagonRegister::V3, HexagonRegister::V2)),
            (HexagonRegister::W2, (HexagonRegister::V5, HexagonRegister::V4)),
            (HexagonRegister::W3, (HexagonRegister::V7, HexagonRegister::V6)),
            (HexagonRegister::W4, (HexagonRegister::V9, HexagonRegister::V8)),
            (HexagonRegister::W5, (HexagonRegister::V11, HexagonRegister::V10)),
            (HexagonRegister::W6, (HexagonRegister::V13, HexagonRegister::V12)),
            (HexagonRegister::W7, (HexagonRegister::V15, HexagonRegister::V14)),
            (HexagonRegister::W8, (HexagonRegister::V17, HexagonRegister::V16)),
            (HexagonRegister::W9, (HexagonRegister::V19, HexagonRegister::V18)),
            (HexagonRegister::W10, (HexagonRegister::V21, HexagonRegister::V20)),
            (HexagonRegister::W11, (HexagonRegister::V23, HexagonRegister::V22)),
            (HexagonRegister::W12, (HexagonRegister::V25, HexagonRegister::V24)),
            (HexagonRegister::W13, (HexagonRegister::V27, HexagonRegister::V26)),
            (HexagonRegister::W14, (HexagonRegister::V29, HexagonRegister::V28)),
            (HexagonRegister::W15, (HexagonRegister::V31, HexagonRegister::V30)),
            (HexagonRegister::WR0, (HexagonRegister::V0, HexagonRegister::V1)),
            (HexagonRegister::WR1, (HexagonRegister::V2, HexagonRegister::V3)),
            (HexagonRegister::WR2, (HexagonRegister::V4, HexagonRegister::V5)),
            (HexagonRegister::WR3, (HexagonRegister::V6, HexagonRegister::V7)),
            (HexagonRegister::WR4, (HexagonRegister::V8, HexagonRegister::V9)),
            (HexagonRegister::WR5, (HexagonRegister::V10, HexagonRegister::V11)),
            (HexagonRegister::WR6, (HexagonRegister::V12, HexagonRegister::V13)),
            (HexagonRegister::WR7, (HexagonRegister::V14, HexagonRegister::V15)),
            (HexagonRegister::WR8, (HexagonRegister::V16, HexagonRegister::V17)),
            (HexagonRegister::WR9, (HexagonRegister::V18, HexagonRegister::V19)),
            (HexagonRegister::WR10, (HexagonRegister::V20, HexagonRegister::V21)),
            (HexagonRegister::WR11, (HexagonRegister::V22, HexagonRegister::V23)),
            (HexagonRegister::WR12, (HexagonRegister::V24, HexagonRegister::V25)),
            (HexagonRegister::WR13, (HexagonRegister::V26, HexagonRegister::V27)),
            (HexagonRegister::WR14, (HexagonRegister::V28, HexagonRegister::V29)),
            (HexagonRegister::WR15, (HexagonRegister::V30, HexagonRegister::V31)),
            (HexagonRegister::VQ0, (HexagonRegister::W1, HexagonRegister::W0)),
            (HexagonRegister::VQ1, (HexagonRegister::W3, HexagonRegister::W2)),
            (HexagonRegister::VQ2, (HexagonRegister::W5, HexagonRegister::W4)),
            (HexagonRegister::VQ3, (HexagonRegister::W7, HexagonRegister::W6)),
            (HexagonRegister::VQ4, (HexagonRegister::W9, HexagonRegister::W8)),
            (HexagonRegister::VQ5, (HexagonRegister::W11, HexagonRegister::W10)),
            (HexagonRegister::VQ6, (HexagonRegister::W13, HexagonRegister::W12)),
            (HexagonRegister::VQ7, (HexagonRegister::W15, HexagonRegister::W14))
        ]);
}

impl RegpairHandler {
    fn get_pairs_from_archregister(
        register: ArchRegister,
    ) -> Option<(HexagonRegister, HexagonRegister)> {
        // WARN: this assumes the registers are defined contiguously
        match register {
            ArchRegister::Basic(BasicArchRegister::Hexagon(reg)) => REGPAIR_MAP.get(&reg).copied(),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
pub struct RegpairHandler;
impl<T: CpuBackend> RegisterCallback<T> for RegpairHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        let (reg_hi, reg_lo) = Self::get_pairs_from_archregister(register)
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
            "regpair read_pair: reg_lo {reg_lo} lo {lo} reg_hi {reg_hi} hi {hi} combined {combined}"
        );

        Ok(combined.into())
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        // must be 64 bit for this handler
        assert_eq!(value.size(), 8);

        let (reg_hi, reg_lo) = Self::get_pairs_from_archregister(register)
            .ok_or(anyhow!("could not get registers to write from"))?;

        let write_val = value.to_u64().ok_or(RegisterHandleError::Other(anyhow!(
            "could not get 64 bit value to write to register pair"
        )))?;

        let lo = (write_val & 0xffffffff) as u32;
        let hi = ((write_val >> 32) & 0xffffffff) as u32;

        trace!("regpair write_pair: lo {lo} hi {hi}");

        // NOTE: would this not cause a bug because write_register just calls this method
        // infinitely and recurisvely?
        cpu.write_register(reg_lo, lo)
            .map_err(|e| RegisterHandleError::Other(e.into()))?;
        cpu.write_register(reg_hi, hi)
            .map_err(|e| RegisterHandleError::Other(e.into()))?;

        Ok(())
    }
}

// TODO: when we implement, just do it in the normal Regpair handler.
#[derive(Debug, Default)]
pub struct VectorRegpairQuadStub;
impl<T: CpuBackend> RegisterCallback<T> for VectorRegpairQuadStub {
    fn read(
        &mut self,
        _register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        debug!("vector register pair/quad read");
        Ok(0u32.into())
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        _value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        debug!("vector register pair/quad write");
        Ok(())
    }
}

// TODO: vector register pairs

pub fn add_register_pair_handlers<S>(spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>) {
    let register_manager = &mut spec.register_manager;
    for reg in REGPAIR_MAP.keys() {
        trace!("adding regpair handler for {reg}");
        register_manager
            .add_handler(*reg, RegpairHandler)
            .expect("couldn't add regpair handler");
    }
}

pub fn add_vector_register_pair_handlers<S>(spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>) {
    let register_manager = &mut spec.register_manager;
    for reg in VECTOR_REGPAIR_MAP.keys() {
        trace!("adding vector regpair handler for {reg}");
        register_manager
            .add_handler(*reg, VectorRegpairQuadStub)
            .expect("couldn't add vector regpair handler");
    }
}
