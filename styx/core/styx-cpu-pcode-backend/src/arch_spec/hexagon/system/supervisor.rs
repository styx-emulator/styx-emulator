// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use log::{debug, trace};
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

#[derive(Debug)]
pub struct CrSwap {}

impl<T: CpuBackend> CallOtherCallback<T> for CrSwap {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let rx_x = &inputs[0];
        let sgp = &inputs[1];

        let tmp_rx_x = cpu
            .read(rx_x)
            .with_context(|| "couldn't read Rx/Rxx for crswap")?;
        let sgp_val = cpu
            .read(sgp)
            .with_context(|| "couldn't read SGP for crswap")?;

        cpu.write(rx_x, sgp_val)
            .with_context(|| "couldn't write SGP to Rx/Rxx")?;
        cpu.write(sgp, tmp_rx_x)
            .with_context(|| "couldn't write Rx/Rxx (tmp) to SGP")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_supervisor_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Crswap, CrSwap {})
        .unwrap();
}
