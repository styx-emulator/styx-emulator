// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use log::{info, trace};
use styx_cpu_type::arch::hexagon::{register_fields::Syscfg, HexagonRegister};
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::Mmu,
};

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    HexagonPcodeBackend, PCodeStateChange,
};

/// Handle the isync instruction, see 11.9.3 "Instruction synchronization."
///
/// This will be called after the SYSCFG register is set, so we can update
/// internal emulation state based on SYSCFG sets here.
///
/// FIXME: multicore (manual mentions when "TID" register is set, make sure there are
/// no threading side effects that need to be dealt with here)
#[derive(Debug)]
pub struct IsyncHandler {}

impl<T: CpuBackend> CallOtherCallback<T> for IsyncHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let syscfg = Syscfg::new_with_raw_value(
            cpu.read_register::<u32>(HexagonRegister::SysCfg)
                .with_context(|| "couldn't read syscfg")?,
        );

        // As mentioned above, this should be called after syscfg is set.
        // Note that syscfg is set for when the MMU is enabled, so we will handle that
        // now.
        if syscfg.mmuen() {
            info!("hexagon: (re)enabling MMU at {:x?}", cpu.pc());
            mmu.tlb.enable_code_address_translation()?;
            mmu.tlb.enable_data_address_translation()?;
        } else {
            info!("hexagon: disabling MMU at {:x?}", cpu.pc());
            mmu.tlb.disable_code_address_translation()?;
            mmu.tlb.disable_data_address_translation()?;
        }

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct SynchtHandler {}

impl<T: CpuBackend> CallOtherCallback<T> for SynchtHandler {
    fn handle(
        &mut self,
        _cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        trace!("syncht stub");
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_sync_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Isync, IsyncHandler {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Syncht, SynchtHandler {})
        .unwrap();
}
