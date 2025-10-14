// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use log::info;
use styx_cpu_type::arch::hexagon::HexagonRegister;
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

use super::regs::Syscfg;

/// Handle the isync instruction, see 11.9.3 "Instruction synchronization."
///
/// This will be called after the SYSCFG register is set, so we can update
/// internal emulation state based on SYSCFG sets here.
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
            info!("hexagon: enabling MMU");
            mmu.tlb.enable_code_address_translation()?;
            mmu.tlb.enable_data_address_translation()?;
        }

        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_isync_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Isync, IsyncHandler {})
        .unwrap();
}
