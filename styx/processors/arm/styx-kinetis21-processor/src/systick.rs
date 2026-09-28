// SPDX-License-Identifier: BSD-2-Clause
use std::sync::{Arc, Mutex};
use styx_core::event_controller::{PeripheralTickCtx, RaisedIrqs};
use styx_core::hooks::MemoryWriteHook;
use styx_core::prelude::*;
use tracing::debug;

const SYSTICK_IRQN: ExceptionNumber = -1;
const SYSTICK_PERIOD: u64 = 10000;

/// Inner state shared between the [`SysTickTimer`] peripheral and its
/// memory-mapped register hook.
#[derive(Default)]
struct SysTickState {
    guest_enabled: bool,
    interrupt_enabled: bool,
    internal_counter: u64,
}

pub struct SysTickTimer {
    inner: Arc<Mutex<SysTickState>>,
}

impl Peripheral for SysTickTimer {
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![SYSTICK_IRQN]
    }

    fn tick(&mut self, ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
        let mut raised = RaisedIrqs::none();
        let mut state = self.inner.lock().unwrap();
        if state.guest_enabled {
            let _ = state
                .internal_counter
                .saturating_add(ctx.delta.simulated_time);

            if state.internal_counter >= SYSTICK_PERIOD {
                state.internal_counter = 0;

                // TODO: set COUNTFLAG bit in SYST_CSR

                if state.interrupt_enabled {
                    debug!("SysTick: Raising Interrupt");
                    raised.push(SYSTICK_IRQN);
                }
            }
        }

        Ok(raised)
    }

    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        proc.vcpus[0].cpu.mem_write_hook(
            SYST_CSR,
            SYST_CALIB,
            Box::new(SysTickWHook {
                inner: self.inner.clone(),
            }),
        )?;

        Ok(())
    }

    fn name(&self) -> &str {
        "SysTick Timer"
    }
    fn reset(&mut self, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        let mut state = self.inner.lock().unwrap();
        state.guest_enabled = false;
        state.interrupt_enabled = false;
        state.internal_counter = 0;

        Ok(())
    }
}

impl SysTickTimer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SysTickState::default())),
        }
    }
}

const SYST_CSR: u64 = 0xE000_E010;
const SYST_CVR: u64 = 0xE000_E018;
const SYST_CALIB: u64 = 0xE000_E01C;

struct SysTickWHook {
    inner: Arc<Mutex<SysTickState>>,
}

impl MemoryWriteHook for SysTickWHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let value = u32::from_le_bytes(data[0..4].try_into().unwrap());

        match address {
            SYST_CSR => {
                // TODO: add logic for disabling timer
                let mut clock = self.inner.lock().unwrap();

                if (value & 0x1) > 0 {
                    clock.guest_enabled = true;
                    debug!("SysTick Counter Enabled");
                }
                if (value & 0x2) > 0 {
                    clock.interrupt_enabled = true;
                    debug!("SysTick Interrupt Enabled");
                }
            }
            SYST_CVR => {
                // writing to the CVR resets the CVR to zero
                proc.mmu.write_data(SYST_CVR, &[0, 0, 0, 0]).unwrap();
            }
            _ => (),
        }

        Ok(())
    }
}
