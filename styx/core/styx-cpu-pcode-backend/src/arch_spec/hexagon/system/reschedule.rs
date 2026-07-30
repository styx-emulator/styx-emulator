// SPDX-License-Identifier: BSD-2-Clause
//! In Hexagon, according to the function resched in QUIC QEMU (branch hex-next),
//! and the "DSP OS QuRT" page in the SDK manual, QuRT has preemptive multitasking
//! that is assisted by the hardware. This assistance is implemented in this file.
//!
//! According to QEMU (target/hexagon/op_helper.c and target/hexagon/translate.c),
//! the times when we should check for a reschedule is when the setprio instruction is invoked,
//! or when the bestwait or schedcfg registers are written.

use std::str::FromStr;

use as_any::Downcast;
use log::warn;
use styx_cpu_type::arch::hexagon::{register_fields::Stid, HexagonRegister};
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

fn resched() {}

#[derive(Debug)]
pub struct SetprioHandler {}

/// See 11.9.2 SYSTEM MONITOR, "Set the priority for a thread"
/// in the Hexagon manual for more information.
impl<T: CpuBackend> CallOtherCallback<T> for SetprioHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // From 11.9.2 "Set the priority for a thread,"
        //
        // The first input to setprio is a predicate register containing the thread ID
        // that indicates the thread whose priority should be set. The second input is
        // a priority value.

        // To find the true thread ID whose priority should be set,
        // the predicate register is ANDed with a mask that is
        // ((1 << NUM_THREADS) - 1); a mask that is exactly NUM_THREADS
        // ones.

        // Predicate registers are 8 bits.
        let predicate_thread =
            cpu.read(&inputs[0])
                .with_context(|| "couldn't read predicate register with thread ID for setprio")?
                .to_u64()
                .with_context(|| "couldn't get setprio thread as u64")? as u8;

        // The priority field in the Stid register is only 8 bits, so we can truncate this to 8 bits as well.
        let priority = cpu
            .read(&inputs[1])
            .with_context(|| "couldn't read priority for setprio")?
            .to_u64()
            .with_context(|| "couldn't get setprio priority as u64")? as u8;

        panic!("setprio called with {predicate_thread:x} {priority:x}");

        /*let pcode_backend = cpu
            .downcast_ref::<HexagonPcodeBackend>()
            .with_context(|| "expected a Hexagon pcode backend!")?;

        let thread_mask = (1 << pcode_backend.num_hthreads()) - 1;

        // Right now, we only have one thread.
        // Do nothing if we are trying to set the priority on a different thread.
        let htid = thread_mask & predicate_thread;
        if htid != 0 {
            warn!("setprio is for thread");
            Ok(PCodeStateChange::Fallthrough)
        } else {
            let stid = Stid::new_with_raw_value(
                cpu.read_register::<u32>(HexagonRegister::Stid)
                    .with_context(|| "couldn't get stid")?,
            );

            cpu.write_register(
                HexagonRegister::Stid,
                stid.with_prio(priority as u8).raw_value(),
            );

            // Triger resched
            resched();

            Ok(PCodeStateChange::Fallthrough)
        }*/
    }
}

pub fn add_reschedule<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Setprio, SetprioHandler {})
        .unwrap();
}
