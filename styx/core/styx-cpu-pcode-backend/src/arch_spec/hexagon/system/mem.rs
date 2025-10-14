// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use log::info;
use styx_cpu_type::arch::hexagon::HexagonRegister;
use styx_errors::anyhow::Context;
use styx_pcode::{
    pcode::{SpaceName, VarnodeData},
    sla::SlaUserOps,
};
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
pub struct MemHandler {}

impl<T: CpuBackend> CallOtherCallback<T> for MemHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let reg_s = &inputs[0];
        let reg_t = &inputs[1];

        let output = output
            .as_ref()
            .expect("memw_phys does not have an output register");

        assert_eq!(reg_s.space, SpaceName::Register);
        assert_eq!(reg_t.space, SpaceName::Register);

        let rs = cpu
            .read(reg_s)
            .with_context(|| "couldn't read Rs in memw_phys")?
            .to_u64()
            .with_context(|| "Rs is over 64 bits in memw_phys")?;
        let rt = cpu
            .read(reg_t)
            .with_context(|| "couldn't read Rt in memw_phys")?
            .to_u64()
            .with_context(|| "Rt is over 64 bits in memw_phys")?;

        assert_eq!(output.space, SpaceName::Register);
        assert_eq!(output.size, 4);

        // 11.9.2 "load from physical address"
        let input = (rs & 0x7ff) | (rt << 11);

        info!("memw_phys reading from {input:x}, rs {rs:x} rt {rt:x}");

        let output_data = mmu
            .read_u32_le_phys_data(input)
            .with_context(|| "couldn't read from physical memory location")?;

        info!("memw_phys read {output_data:x}");

        cpu.write(&output, output_data.into())
            .with_context(|| "couldn't write physical memory value to register")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_mem_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::MemwPhys, MemHandler {})
        .unwrap();
}
