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
use styx_core::prelude::*;
use tracing::debug;

const SYSTICK_IRQN: ExceptionNumber = -1;
const SYSTICK_PERIOD: u64 = 10000;

pub struct SysTickTimer {
    guest_enabled: bool,
    interrupt_enabled: bool,
    internal_counter: u64,
}

impl Peripheral for SysTickTimer {
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![SYSTICK_IRQN]
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        if self.guest_enabled {
            let _ = self.internal_counter.saturating_add(delta.count);

            if self.internal_counter >= SYSTICK_PERIOD {
                self.internal_counter = 0;

                // TODO: set COUNTFLAG bit in SYST_CSR

                if self.interrupt_enabled {
                    debug!("SysTick: Raising Interrupt");
                    event_controller.latch(SYSTICK_IRQN)?;
                }
            }
        }

        Ok(())
    }

    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        proc.core
            .cpu
            .mem_write_hook(SYST_CSR, SYST_CALIB, Box::new(systick_w_hook))?;

        Ok(())
    }

    fn name(&self) -> &str {
        "SysTick Timer"
    }
    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.guest_enabled = false;
        self.interrupt_enabled = false;
        self.internal_counter = 0;

        Ok(())
    }
}

impl SysTickTimer {
    pub fn new() -> Self {
        Self {
            guest_enabled: false,
            interrupt_enabled: false,
            internal_counter: 0,
        }
    }
}

const SYST_CSR: u64 = 0xE000_E010;
const SYST_CVR: u64 = 0xE000_E018;
const SYST_CALIB: u64 = 0xE000_E01C;

fn systick_w_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let value = u32::from_le_bytes(data[0..4].try_into().unwrap());

    match address {
        SYST_CSR => {
            // TODO: add logic for disabling timer
            let clock = proc
                .event_controller
                .peripherals
                .get::<SysTickTimer>()
                .unwrap();

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
