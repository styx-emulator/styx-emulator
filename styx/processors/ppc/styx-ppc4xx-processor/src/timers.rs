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
//! PowerPC 4xx Timers
//!
//! Information comes from the PowerPC 405 Embedded Processor Core User’s Manual.
//!
//! The PowerPC has 4 timer based mechanisms:
//!  - Programmable Interrupt Timer (PIT)
//!  - Fixed Interval Timer (FIT)
//!  - Time Base (TBU, TBL)
//!  - Watchdog Timer
//!
//! Implemented currently are the Time Base and PIT.
//!
//! ## Timer Base Clock
//!
//! All timer facilities run of off the same base clock which is different than
//! the processor clock rate. The emulated base clock is defined in
//! [TIMER_BASE_CLOCK_HZ]. Clocking is emulated in the [TimersInner::update()]
//! method which is called at intervals by the [timer_cpu_loop_hook()].
//!
//! [TimersInner::update()] is not called at base clock frequency, instead it is
//! called at a fractional frequency (defined in [timer_cpu_loop_hook()]) and
//! incrementors/decrementors are modified by the inverse fraction of that
//! frequency. This way timers react with a fixed frequency that doesn't bog
//! down emulator performance.
//!
//! ## Timer Base (register)
//!
//! Timer Base is documented in *Section 6.1* and in [update_timer_base()].
//!
//! ## Programmable Interrupt Timer (PIT)
//!
//! The PIT is documented in *Section 6.2* and in [ProgrammableInterruptTimer].
//!
use bitfield_struct::bitfield;
use std::sync::{Arc, Mutex};
use styx_core::cpu::arch::ppc32::Ppc32Register;
use styx_core::errors::UnknownError;
use styx_core::prelude::*;

use crate::core_event_controller::{Event, Register};

const CPU_CLOCK_HZ: f64 = 400_000_000.;

/// Timer clock speed in hertz.
const TIMER_BASE_CLOCK_HZ: f64 = 1_666_666.;

pub struct Timers {
    inner: Arc<Mutex<TimersInner>>,
}

impl Timers {
    pub fn new(cpu: &mut dyn CpuBackend) -> Self {
        let inner = Arc::new(Mutex::new(TimersInner::new(cpu)));
        Self { inner }
    }
}

struct TimersInner {
    control: Register,
    _status: Register,
    pit: ProgrammableInterruptTimer,
}

impl Peripheral for Timers {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        let timers = self.inner.clone();
        let mut current_instruction = 0;

        log::debug!("timers initialized");
        proc.core.cpu.code_hook(
            u64::MIN,
            u64::MAX,
            Box::new(move |proc: CoreHandle| {
                timer_cpu_loop_hook(proc, &mut current_instruction, timers.as_ref());
                Ok(())
            }),
        )?;
        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        [
            Event::ProgrammableInterruptTimer,
            Event::FixedIntervalTimerInterrupt,
        ]
        .into_iter()
        .map(|e| e.event_number() as i32)
        .collect()
    }
    fn name(&self) -> &str {
        "Timers"
    }
}

impl TimersInner {
    fn new(cpu: &mut dyn CpuBackend) -> Self {
        Self {
            control: Register::new(Ppc32Register::Tcr, cpu),
            _status: Register::new(Ppc32Register::Tsr, cpu),
            pit: ProgrammableInterruptTimer::new(cpu),
        }
    }

    fn code_hook(&mut self, proc: &mut CoreHandle) {
        self.control.update(proc.cpu, |cpu, value| {
            let pc = cpu.pc().unwrap();
            log::debug!("TCR new value! {value:x} @ 0x{pc:X}");
            let tcr = TimerControlRegisterBitfield::from_bits(value);

            self.pit.enabled = tcr.pit_interrupt_enable();

            value
        })
    }

    fn update(&mut self, proc: &mut CoreHandle, timer_clocks: u32) {
        self.code_hook(proc);
        self.pit.update(proc, timer_clocks);
        update_timer_base(proc.cpu, timer_clocks);
    }
}

/// Programmable Interrupt Timer control.
///
/// Documented in section 6.2, the PIT decrements at the same rate as the time
/// base ([update_timer_base()]).
///
/// A PIT value of 1 (i.e. after decrementing) triggers the exception if MSR's
/// External Exceptions is enabled and TCR's PIT Interrupt Enable is enabled.
///
/// SHORTCOMING: Currently the msr and tcr will set the enable of the pit
/// exception instead of checking both conditions. This should be changed to
/// instead check the condition when checking for enabled interrupts instead of
/// updating when registers are update.
///
/// After hitting 1, the behavior depends on the value of the tcr's auto reload
/// enable bit. If it's set, the pit should reset back to the last value that
/// was written to it. If auto reload is disabled, the pit should sit at 0.
struct ProgrammableInterruptTimer {
    /// The auto-reload value after PIT hits 1, set by a write to the PIT.
    auto_reload: u32,
    last_value: u32,
    enabled: bool,
}
impl ProgrammableInterruptTimer {
    fn new(cpu: &mut dyn CpuBackend) -> Self {
        let top = 100000u32;
        cpu.write_register(Ppc32Register::Pit, top).unwrap();
        let last_value = top;
        Self {
            auto_reload: top,
            last_value,
            enabled: false,
        }
    }

    fn update(&mut self, proc: &mut CoreHandle, timer_clocks: u32) {
        let new_pit = proc.cpu.read_register::<u32>(Ppc32Register::Pit).unwrap();
        if new_pit != self.last_value {
            log::debug!("pit set to {new_pit}");
            // new write
            self.auto_reload = new_pit;
            self.last_value = new_pit;
        }

        // info!("HERHEHR: enabled: {} new_pit: {}", self.enabled, new_pit);
        // will not decrement if 0
        if self.enabled && new_pit != 0 {
            let final_pit = {
                let pit_subtract_option = new_pit.checked_sub(timer_clocks);
                if let Some(new_pit) = pit_subtract_option {
                    new_pit
                } else {
                    proc.event_controller
                        .latch(Event::ProgrammableInterruptTimer.event_number() as i32)
                        .unwrap();
                    let tcr = TimerControlRegisterBitfield::load(proc.cpu);
                    if tcr.auto_reload_enable() {
                        self.auto_reload
                    } else {
                        0
                    }
                }
            };

            proc.cpu
                .write_register(Ppc32Register::Pit, final_pit)
                .unwrap();
            self.last_value = final_pit;
        }
    }
}

/// Code hook to increment Timer Base Clock and update all other timers.
fn timer_cpu_loop_hook(
    mut proc: CoreHandle,
    current_instruction: &mut u64,
    timers: &Mutex<TimersInner>,
) {
    /// Update timer_increment after N instructions. Improves performance by
    /// reducing timers locks and register writes.
    const UPDATE_INSTRUCTIONS: f64 = 1_000.;
    /// Ratio of the Timer Base Clock to the CPU Clock.
    ///
    /// This will be used to ensure accurate timers based on how fast the CPU is
    /// executing.
    const TIMER_CLOCK_RATIO: f64 = TIMER_BASE_CLOCK_HZ / CPU_CLOCK_HZ;
    /// Scale up how fast the timer base clock increments.
    ///
    /// This makes the emulation innaccruate but ramps up PIT/FIT to normal
    /// speeds given slow emulation
    const SCALE: f64 = 1500.0;

    /// Amount to increment timers by to maintain the same clock speed.
    ///
    /// Timers incremented by `TIMER_INCREMENT` every `UPDATE_INSTRUCTIONS` instructions.
    const TIMER_INCREMENT: u32 = (UPDATE_INSTRUCTIONS * TIMER_CLOCK_RATIO * SCALE) as u32;
    *current_instruction += 1;
    if *current_instruction > UPDATE_INSTRUCTIONS as u64 {
        *current_instruction = 0;

        let mut timers = timers.lock().unwrap();
        timers.update(&mut proc, TIMER_INCREMENT);
    }
}

/// Updates timer base after timers update.
///
/// Documented in **Section 6.1**, the Timer Base is a 64 bit int that is
/// incremented according to the timer base clock. This
/// is called less frequently during timers update so we increment by
/// a passed `timer_increment`.
fn update_timer_base(cpu: &mut dyn CpuBackend, timer_increment: u32) {
    let lower_base = cpu.read_register::<u32>(Ppc32Register::TblW).unwrap() as u64;
    let upper_base = cpu.read_register::<u32>(Ppc32Register::TbuW).unwrap() as u64;
    let new_total = ((upper_base << 32) | lower_base).wrapping_add(timer_increment as u64);
    let new_lower = new_total as u32;
    let new_upper = ((new_total >> 32) & u32::MAX as u64) as u32;

    cpu.write_register(Ppc32Register::TblW, new_lower).unwrap();
    cpu.write_register(Ppc32Register::TbuW, new_upper).unwrap();
}

/// Timer Control Register (TCR) ready to be parsed.
#[bitfield(u32)]
struct TimerControlRegisterBitfield {
    /// reserved
    #[bits(22)]
    __: usize,
    auto_reload_enable: bool,
    fit_interrupt_enable: bool,
    #[bits(2)]
    fit_period: u8,
    pit_interrupt_enable: bool,
    watchdog_interrupt_enable: bool,
    #[bits(2)]
    watchdog_reset_control: u8,
    #[bits(2)]
    watchdog_period: u8,
}

impl TimerControlRegisterBitfield {
    fn load(cpu: &mut dyn CpuBackend) -> Self {
        Self::from_bits(cpu.read_register::<u32>(Ppc32Register::Tcr).unwrap())
    }
}
