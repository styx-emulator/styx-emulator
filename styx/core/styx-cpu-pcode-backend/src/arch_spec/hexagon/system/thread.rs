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

/// Handle the Hexagon wait instruction. Stubbed for now.
#[derive(Debug)]
pub struct WaitHandler {}

impl<T: CpuBackend> CallOtherCallback<T> for WaitHandler {
    fn handle(
        &mut self,
        _cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_thread_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Wait, WaitHandler {})
        .unwrap();
}
