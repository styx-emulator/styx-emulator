// SPDX-License-Identifier: BSD-2-Clause
use std::mem::offset_of;
use std::sync::{Arc, Mutex};
use styx_core::event_controller::{PeripheralTickCtx, RaisedIrqs};
use styx_core::hooks::{MemoryReadHook, MemoryWriteHook};
use styx_core::prelude::*;
use tracing::trace;

// base FTM type
use super::mk21f12_sys::FTM_Type;

// interrupt numbers
use super::mk21f12_sys::{IRQn_FTM0_IRQn, IRQn_FTM1_IRQn, IRQn_FTM2_IRQn, IRQn_FTM3_IRQn};

// ftm base addresses
use super::mk21f12_sys::{FTM0_BASE, FTM1_BASE, FTM2_BASE, FTM3_BASE};

const FLEXIBLE_TIMER_DURATION: u64 = 10000;

pub struct FlexibleTimer {
    num: u32,
    base_address: u32,
    irqn: ExceptionNumber,
    running: bool,
    guest_enabled: bool,
    timer_duration: u64,
    internal_counter: u64,
    interrupt_raised: bool,
}

impl FlexibleTimer {
    pub fn new(num: u32, base_address: u32, irqn: ExceptionNumber) -> Self {
        Self {
            num,
            base_address,
            irqn,
            running: false,
            guest_enabled: false,
            timer_duration: FLEXIBLE_TIMER_DURATION,
            internal_counter: 0,
            interrupt_raised: false,
        }
    }

    fn register_hooks(
        timer: &Arc<Mutex<FlexibleTimer>>,
        cpu: &mut dyn CpuBackend,
    ) -> Result<(), UnknownError> {
        let base_address = timer.lock().unwrap().base_address;
        let type_size = core::mem::size_of::<FTM_Type>() as u64;

        // blanket mem read hook
        cpu.mem_read_hook(
            base_address as u64,
            base_address as u64 + type_size,
            Box::new(BlanketMemReadHook {
                timer: timer.clone(),
            }),
        )?;

        // blanket mem write hook
        cpu.mem_write_hook(
            base_address as u64,
            base_address as u64 + type_size,
            Box::new(BlanketMemWriteHook {
                timer: timer.clone(),
            }),
        )?;

        // check if guest is enabling / disabling the timer
        let ftm_sc = base_address as u64 + offset_of!(FTM_Type, SC) as u64;
        cpu.mem_write_hook(
            ftm_sc,
            ftm_sc + 4,
            Box::new(FtmScWriteHook {
                timer: timer.clone(),
            }),
        )?;
        cpu.mem_read_hook(
            ftm_sc,
            ftm_sc + 4,
            Box::new(FtmScReadHook {
                timer: timer.clone(),
            }),
        )?;

        Ok(())
    }
}

impl Peripheral for FlexibleTimer {
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.irqn]
    }

    fn tick(&mut self, ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
        let mut raised = RaisedIrqs::none();
        // if the guest has enabled us
        if self.guest_enabled {
            let _ = self
                .internal_counter
                .saturating_add(ctx.delta.simulated_time);

            if self.internal_counter >= self.timer_duration {
                self.internal_counter = 0;
                self.interrupt_raised = true;
                raised.push(self.irqn);
            }
        }

        Ok(raised)
    }

    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Flexible Timer"
    }

    fn reset(&mut self, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.running = false;
        self.guest_enabled = false;
        self.internal_counter = 0;
        self.interrupt_raised = false;
        Ok(())
    }
}

pub struct FtmController {
    timers: Vec<Arc<Mutex<FlexibleTimer>>>,
}

impl FtmController {
    pub fn new() -> Self {
        Self {
            timers: vec![
                Arc::new(Mutex::new(FlexibleTimer::new(0, FTM0_BASE, IRQn_FTM0_IRQn))),
                Arc::new(Mutex::new(FlexibleTimer::new(1, FTM1_BASE, IRQn_FTM1_IRQn))),
                Arc::new(Mutex::new(FlexibleTimer::new(2, FTM2_BASE, IRQn_FTM2_IRQn))),
                Arc::new(Mutex::new(FlexibleTimer::new(3, FTM3_BASE, IRQn_FTM3_IRQn))),
            ],
        }
    }
}

impl Peripheral for FtmController {
    fn irqs(&self) -> Vec<ExceptionNumber> {
        self.timers
            .iter()
            .flat_map(|x| x.lock().unwrap().irqs())
            .collect()
    }

    fn tick(&mut self, ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
        let mut raised = RaisedIrqs::none();
        for timer in self.timers.iter() {
            raised.extend(timer.lock().unwrap().tick(ctx)?);
        }
        Ok(raised)
    }

    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        for timer in &self.timers {
            FlexibleTimer::register_hooks(timer, proc.vcpus[0].cpu.as_mut())?;
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "FTM Controller"
    }

    fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        for timer in self.timers.iter() {
            timer.lock().unwrap().reset(mmu)?;
        }

        Ok(())
    }
}

struct BlanketMemReadHook {
    timer: Arc<Mutex<FlexibleTimer>>,
}

impl MemoryReadHook for BlanketMemReadHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let ftm = self.timer.lock().unwrap();

        trace!("(R) FTM{} @ [{:#08X}]: {:?}", ftm.num, address, data);
        Ok(())
    }
}

struct BlanketMemWriteHook {
    timer: Arc<Mutex<FlexibleTimer>>,
}

impl MemoryWriteHook for BlanketMemWriteHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let ftm = self.timer.lock().unwrap();

        trace!("(W) FTM{} @ [{:#08X}]: {:?}", ftm.num, address, data);
        Ok(())
    }
}

/// checks the bitfield written to the FTM\[SC\]
struct FtmScWriteHook {
    timer: Arc<Mutex<FlexibleTimer>>,
}

impl MemoryWriteHook for FtmScWriteHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let mut timer = self.timer.lock().unwrap();
        let enabled = (data[0] & 0x40) > 0;
        trace!("(W) FTM{} SC: {:?}", timer.num, data);

        // propagate the enabled / disable
        match enabled {
            true => timer.guest_enabled = true,
            false => timer.guest_enabled = false,
        }

        Ok(())
    }
}

struct FtmScReadHook {
    timer: Arc<Mutex<FlexibleTimer>>,
}

impl MemoryReadHook for FtmScReadHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let timer = self.timer.lock().unwrap();

        trace!("(R) FTM{} SC: {:?}", timer.num, data);

        // enabled, set the overflow bit
        if timer.running && timer.guest_enabled && timer.interrupt_raised {
            data[0] |= 0x80;
            proc.mmu.write_data(address, data).unwrap();
        }

        Ok(())
    }
}
