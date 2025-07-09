// SPDX-License-Identifier: BSD-2-Clause
use std::mem::offset_of;
use styx_core::errors::anyhow::anyhow;
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

    fn register_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        let type_size = core::mem::size_of::<FTM_Type>() as u64;

        // blanket mem read hook
        cpu.mem_read_hook(
            self.base_address as u64,
            self.base_address as u64 + type_size,
            Box::new(blanket_mem_read_hook),
        )?;

        // blanket mem write hook
        cpu.mem_write_hook(
            self.base_address as u64,
            self.base_address as u64 + type_size,
            Box::new(blanket_mem_write_hook),
        )?;

        // check if guest is enabling / disabling the timer
        let ftm_sc = self.base_address as u64 + offset_of!(FTM_Type, SC) as u64;
        cpu.mem_write_hook(ftm_sc, ftm_sc + 4, Box::new(ftm_sc_write_hook))?;
        cpu.mem_read_hook(ftm_sc, ftm_sc + 4, Box::new(ftm_sc_read_hook))?;

        Ok(())
    }
}

impl Peripheral for FlexibleTimer {
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.irqn]
    }

    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        num: ExceptionNumber,
    ) -> Result<(), UnknownError> {
        trace!("Flexible timer {} IRQ{num}::post_event_hook", self.num);
        self.interrupt_raised = false;
        Ok(())
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        // if the guest has enabled us
        if self.guest_enabled {
            let _ = self.internal_counter.saturating_add(delta.count);

            if self.internal_counter >= self.timer_duration {
                self.internal_counter = 0;
                self.interrupt_raised = true;
                event_controller.latch(self.irqn)?;
            }
        }

        Ok(())
    }

    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Flexible Timer"
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.running = false;
        self.guest_enabled = false;
        self.internal_counter = 0;
        self.interrupt_raised = false;
        Ok(())
    }
}

pub struct FtmController {
    timers: Vec<FlexibleTimer>,
}

impl FtmController {
    pub fn new() -> Self {
        Self {
            timers: vec![
                FlexibleTimer::new(0, FTM0_BASE, IRQn_FTM0_IRQn),
                FlexibleTimer::new(1, FTM1_BASE, IRQn_FTM1_IRQn),
                FlexibleTimer::new(2, FTM2_BASE, IRQn_FTM2_IRQn),
                FlexibleTimer::new(3, FTM3_BASE, IRQn_FTM3_IRQn),
            ],
        }
    }

    /// converts an address to the corresponding [`FlexibleTimer`]
    pub fn address_to_timer(&mut self, address: u64) -> Result<&mut FlexibleTimer, UnknownError> {
        let mut out = Err(anyhow!("invalid address"));
        if address >= FTM0_BASE as u64 {
            if address < FTM1_BASE as u64 {
                out = Ok(&mut self.timers[0]);
            } else if address < FTM2_BASE as u64 {
                out = Ok(&mut self.timers[1]);
            } else if address < FTM3_BASE as u64 {
                out = Ok(&mut self.timers[2]);
            } else if address <= (FTM3_BASE as u64 + core::mem::size_of::<FTM_Type>() as u64) {
                out = Ok(&mut self.timers[3]);
            }
        }

        out
    }

    /// Searches for a timer that owns the specific IRQn
    fn irq_to_timer(&mut self, num: ExceptionNumber) -> Result<&mut FlexibleTimer, UnknownError> {
        for timer in self.timers.iter_mut() {
            if timer.irqs().contains(&num) {
                return Ok(timer);
            }
        }

        // no timer matched
        Err(anyhow!("k21 ftm, no irq match"))
    }
}

impl Peripheral for FtmController {
    fn irqs(&self) -> Vec<ExceptionNumber> {
        self.timers.iter().flat_map(|x| x.irqs()).collect()
    }

    fn post_event_hook(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        num: ExceptionNumber,
    ) -> Result<(), UnknownError> {
        let timer = self.irq_to_timer(num)?;
        timer.post_event_hook(cpu, mmu, event_controller, num)
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        for timer in self.timers.iter_mut() {
            timer.tick(cpu, mmu, event_controller, delta)?;
        }
        Ok(())
    }

    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        for timer in &mut self.timers {
            timer.register_hooks(proc.core.cpu.as_mut())?;
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "FTM Controller"
    }

    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        for timer in self.timers.iter_mut() {
            timer.reset(cpu, mmu)?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
fn blanket_mem_read_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let ftm_controller = proc
        .event_controller
        .peripherals
        .get::<FtmController>()
        .unwrap();
    let ftm = ftm_controller.address_to_timer(address).unwrap();

    trace!("(R) FTM{} @ [{:#08X}]: {:?}", ftm.num, address, data);
    Ok(())
}

#[allow(dead_code)]
fn blanket_mem_write_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let ftm_controller = proc
        .event_controller
        .peripherals
        .get::<FtmController>()
        .unwrap();
    let ftm = ftm_controller.address_to_timer(address).unwrap();

    trace!("(W) FTM{} @ [{:#08X}]: {:?}", ftm.num, address, data);
    Ok(())
}

/// checks the bitfield written to the FTM\[SC\]
fn ftm_sc_write_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let ftm_controller = proc
        .event_controller
        .peripherals
        .get::<FtmController>()
        .unwrap();
    let timer = ftm_controller.address_to_timer(address).unwrap();
    let enabled = (data[0] & 0x40) > 0;
    trace!("(W) FTM{} SC: {:?}", timer.num, data);

    // propagate the enabled / disable
    match enabled {
        true => timer.guest_enabled = true,
        false => timer.guest_enabled = false,
    }

    Ok(())
}

fn ftm_sc_read_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let ftm_controller = proc
        .event_controller
        .peripherals
        .get::<FtmController>()
        .unwrap();
    let timer = ftm_controller.address_to_timer(address).unwrap();

    trace!("(R) FTM{} SC: {:?}", timer.num, data);

    // enabled, set the overflow bit
    if timer.running && timer.guest_enabled && timer.interrupt_raised {
        data[0] |= 0x80;
        proc.mmu.write_data(address, data).unwrap();
    }

    Ok(())
}
