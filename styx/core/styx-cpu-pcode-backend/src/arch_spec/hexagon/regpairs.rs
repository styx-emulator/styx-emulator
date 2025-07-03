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
    static ref REGPAIR_MAP: HashMap<(HexagonRegister, HexagonRegister), HexagonRegister> =
        HashMap::from([
            // General
            ((HexagonRegister::D0, HexagonRegister::D15), HexagonRegister::R0),
            // Control
            ((HexagonRegister::C1C0, HexagonRegister::UtimerHi), HexagonRegister::Sa0),
            // System
            ((HexagonRegister::SGP1SGP0, HexagonRegister::S79S78), HexagonRegister::Sgp0),
            // Guest
            ((HexagonRegister::G1G0, HexagonRegister::G31G30), HexagonRegister::Gelr),
        ]);
}

impl RegpairHandler {
    fn get_pairs_from_archregister(
        register: ArchRegister,
    ) -> Option<(HexagonRegister, HexagonRegister)> {
        // WARN: this assumes the registers are defined contiguously
        match register {
            ArchRegister::Basic(BasicArchRegister::Hexagon(reg)) => {
                for ((reg_start, reg_end), reg_map_val) in REGPAIR_MAP.iter() {
                    if let Some(regs) = Self::get_pair(reg, *reg_start, *reg_end, *reg_map_val) {
                        return Some(regs);
                    }
                }

                unreachable!()
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
    for (reg_start, reg_end) in REGPAIR_MAP.keys() {
        let start_val = reg_start
            .to_u32()
            .expect("couldn't get register pair register as int");
        let end_val = reg_end
            .to_u32()
            .expect("couldn't get register pair register as int");

        for i in start_val..(end_val + 1) {
            let reg = HexagonRegister::from_u32(i)
                .expect("couldn't convert register pair reg back to HexagonRegister");
            trace!("adding regpair handler for {}", reg);
            register_manager
                .add_handler(reg, RegpairHandler)
                .expect("couldn't add regpair handler");
        }
    }
}
