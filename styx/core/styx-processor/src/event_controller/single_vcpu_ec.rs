// SPDX-License-Identifier: BSD-2-Clause

use super::*;
use crate::processor::PerVcpuSlice;

/// Event distributor that routes interrupts to vCPU 0.
#[derive(Default)]
pub struct SingleVcpuEventDistributor {}

impl EventDistributorImpl for SingleVcpuEventDistributor {
    fn tick(
        &mut self,
        _delta: &GlobalDelta,
        pending_irqs: &[ExceptionNumber],
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        let vcpu = vcpus.first_mut();
        for irq in pending_irqs {
            vcpu.event_controller.latch(*irq)?;
        }
        Ok(())
    }
}
