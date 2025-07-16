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

use enum_map::{Enum, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use tracing::{debug, trace};

use crate::core_event_controller::{PeripheralId, SicHandle};

/// Timer configuration and runtime state.
///
/// FIXME unimplemented features:
/// - Errors (also in `TIMER_STATUS`)
/// - `TIMER_COUNTER` is not updated nothing
/// - Many `TIMER_CONFIG` options are not implemented
///
#[derive(Default)]
struct TimerState {
    // Timer enabled, bit in `TIMER_ENABLE`.
    enabled: bool,
    // Timer config, sourced from `TIMERx_CONFIG`.
    config: timer_config::Config,
    // Timer period, sourced from `TIMERx_PERIOD`.
    period: u32,
    // Timer width, sourced from `TIMERx_WIDTH`.
    width: u32,
    // Timer interrupt status, `TIMILx` bit sourced from TIMER_STATUS.
    interrupt_status: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum TimerId {
    Zero,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
}

impl TimerId {
    /// 0-7 number of timer
    fn index(self) -> u8 {
        u8::from(self)
    }

    /// Is the bit corresponding to this timer set in value?
    fn mask(self, value: u8) -> bool {
        (value >> self.index()) & 1 > 0
    }
}

impl From<TimerId> for PeripheralId {
    fn from(value: TimerId) -> Self {
        PeripheralId::try_from(32 + value.index()).expect("invalid peripheral id for timer")
    }
}

pub struct TimerContainer {
    system: SicHandle,
    timers: EnumMap<TimerId, Mutex<TimerState>>,
}

impl TimerContainer {
    /// Write to `TIMER_ENABLE` register.
    pub fn timer_enable(&self, timer_enabled_register: u8) {
        for (id, timer) in self.timers.iter() {
            let is_enabled = id.mask(timer_enabled_register);
            if is_enabled {
                timer.lock().unwrap().enabled = true;
                debug!("timer {id:?} enabled");
            }
        }
    }

    /// Write to `TIMER_DISABLE` register.
    pub fn timer_disable(&self, timer_disable_register: u8) {
        for (id, timer) in self.timers.iter() {
            let is_disabled = id.mask(timer_disable_register);
            if is_disabled {
                timer.lock().unwrap().enabled = false;
                debug!("{id:?} disabled");
            }
        }
    }

    /// Iterator over enabled timers.
    pub fn enabled_timers(&self) -> impl Iterator<Item = TimerId> + use<> {
        let a: Vec<_> = self
            .timers
            .iter()
            .filter_map(|(id, per)| per.lock().unwrap().enabled.then_some(id))
            .collect();
        a.into_iter()
    }

    /// Set configuration for timer from `TIMERx_CONFIG` register.
    pub fn timer_config(&self, timer: TimerId, config: u16) {
        let new_config = timer_config::Config::from_config(config);
        debug!("timer {timer:?} config set to {new_config:?}");

        self.timers[timer].lock().unwrap().config = new_config;
    }

    /// Set period for timer from `TIMERx_PERIOD` register.
    pub fn timer_period(&self, timer: TimerId, period: u32) {
        debug!("timer {timer:?} period set to {period:?}");

        self.timers[timer].lock().unwrap().period = period;
    }

    /// Set width for timer from `TIMERx_WIDTH` register.
    pub fn timer_width(&self, timer: TimerId, width: u32) {
        debug!("timer {timer:?} width set to {width:?}");

        self.timers[timer].lock().unwrap().width = width;
    }

    /// Set status for timers using `TIMERx_STATUS` register. Write 1 clears.
    ///
    /// FIXME: Only bits TIMIL0-3 are implemented.
    pub fn timer_status(&self, status: u32) {
        let interrupt_status = status & 0xF;
        assert_eq!(
            interrupt_status, status,
            "full timer status not implemented yet, only timer 0-3 interrupt is implemented."
        );

        for i in 0..=3 {
            if interrupt_status & (1 << i) > 1 {
                // write 1 clear for timer i
                let timer = TimerId::try_from(i).unwrap();
                self.timers[timer].lock().unwrap().interrupt_status = false;
                self.system.unlatch_peripheral(timer);
                debug!("{timer:?} interrupt status cleared");
            }
        }
    }

    /// Timer count was completed. Called from timers peripheral.
    pub fn timer_went_off(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut dyn EventControllerImpl,
        enabled_timer: TimerId,
    ) {
        let mut timer = self.timers[enabled_timer].lock().unwrap();
        timer.interrupt_status = true;
        trace!("timer {enabled_timer:?} triggered, latching peripheral");
        self.system.latch_peripheral(mmu, ev, enabled_timer);
    }

    pub fn new(system: SicHandle) -> Self {
        Self {
            system,
            timers: Default::default(),
        }
    }
}

mod timer_config {
    #![allow(dead_code)]
    /// Bit fields for timer configs. Once the parsing is implemented the dead_code allow can be
    /// removed.

    #[derive(Debug)]
    enum Mode {
        ExtClk,
        PwmOut,
        Reset,
        WdthCap,
    }

    impl ConfigParameter for Mode {
        fn from_config(config: u16) -> Self {
            match config & 0b11 {
                0b00 => Mode::Reset,
                0b01 => Mode::PwmOut,
                0b10 => Mode::WdthCap,
                0b11 => Mode::ExtClk,
                // impossible
                _ => panic!("unexpected mode"),
            }
        }
    }

    #[derive(Debug)]
    enum PulseHi {
        Negative,
        Position,
    }
    impl BooleanConfigParameter for PulseHi {
        fn position() -> u8 {
            2
        }
        fn low() -> Self {
            Self::Negative
        }
        fn high() -> Self {
            Self::Position
        }
    }

    #[derive(Debug)]
    enum PeriodCount {
        EndOfPeriod,
        EndOfWidth,
    }
    impl BooleanConfigParameter for PeriodCount {
        fn position() -> u8 {
            3
        }

        fn low() -> Self {
            Self::EndOfWidth
        }

        fn high() -> Self {
            Self::EndOfPeriod
        }
    }

    #[derive(Debug)]
    enum InterruptRequest {
        Disabled,
        Enabled,
    }
    impl BooleanConfigParameter for InterruptRequest {
        fn position() -> u8 {
            4
        }

        fn low() -> Self {
            Self::Disabled
        }

        fn high() -> Self {
            Self::Enabled
        }
    }

    // TODO, the meaning of values depends on Mode
    #[derive(Debug)]
    enum InputSelect {
        One,
        Zero,
    }

    #[derive(Debug)]
    enum OutputPadDisable {
        Disable,
        Enable,
    }
    impl BooleanConfigParameter for OutputPadDisable {
        fn position() -> u8 {
            6
        }

        fn low() -> Self {
            Self::Enable
        }

        fn high() -> Self {
            Self::Disable
        }
    }

    #[derive(Debug)]
    enum ClockSelect {
        PwmClock,
        System,
    }

    #[derive(Debug)]
    enum ToggleHi {
        EffectiveAlternates,
        Programmed,
    }

    #[derive(Debug)]
    enum EmulationBehavior {
        Continues,
        Stops,
    }

    #[derive(Debug)]
    enum TimerError {
        CounterOverflow,
        PeriodRegisterProgramming,
        PulseWidthProgramming,
    }

    pub trait ConfigParameter {
        fn from_config(config: u16) -> Self;
    }
    trait BooleanConfigParameter {
        fn position() -> u8;
        fn low() -> Self;
        fn high() -> Self;
    }
    impl<T: BooleanConfigParameter> ConfigParameter for T {
        fn from_config(config: u16) -> Self {
            let value = ((config >> Self::position()) & 1) > 0;

            if value {
                Self::high()
            } else {
                Self::low()
            }
        }
    }

    #[derive(Debug)]
    pub struct Config {
        mode: Mode,
        pulse_hi: PulseHi,
        period_count: PeriodCount,
        interrupt_enable: InterruptRequest,
        output_pad_disabled: OutputPadDisable,
    }

    impl Config {
        pub fn from_config(config: u16) -> Self {
            Self {
                mode: ConfigParameter::from_config(config),
                pulse_hi: ConfigParameter::from_config(config),
                period_count: ConfigParameter::from_config(config),
                interrupt_enable: ConfigParameter::from_config(config),
                output_pad_disabled: ConfigParameter::from_config(config),
            }
        }
    }

    impl Default for Config {
        fn default() -> Self {
            Self::from_config(0)
        }
    }
}
