// SPDX-License-Identifier: BSD-2-Clause
mod timer;

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use derivative::Derivative;
use styx_core::event_controller::{PeripheralTickCtx, RaisedIrqs};
use styx_core::hooks::MemoryWriteHook;
use styx_core::prelude::*;
use timer::*;
use tokio::time;
use tracing::{debug, warn};

use styx_blackfin_sys::bf512 as sys;

use crate::core_event_controller::SicHandle;

#[derive(Clone, Default)]
pub struct TimerLoopStatus {
    triggered: Arc<AtomicBool>,
}

#[derive(Derivative)]
pub struct Timers {
    timers: Arc<TimerContainer>,
    loop_status: TimerLoopStatus,
    running: bool,
}
async fn timer_loop(status: TimerLoopStatus) {
    let mut interval = time::interval(Duration::from_millis(100));
    loop {
        // sleep for our sleep time
        interval.tick().await;
        status.triggered.store(true, Ordering::Relaxed);
    }
}

impl Timers {
    pub fn new(system: SicHandle) -> Self {
        Self {
            timers: Arc::new(TimerContainer::new(system)),
            loop_status: TimerLoopStatus::default(),
            running: false,
        }
    }
}

impl Peripheral for Timers {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        debug!("Timers init");

        // let clock = self.weak_ref.upgrade().unwrap();

        let status = self.loop_status.clone();
        // start our stuff
        proc.runtime
            .handle()
            .spawn(async move { timer_loop(status).await });

        proc.vcpus[0].cpu.mem_write_hook(
            sys::TIMER0_CONFIG as u64,
            sys::TIMER_STATUS as u64,
            Box::new(TimerRegisterWriteHook {
                timers: self.timers.clone(),
            }),
        )?;

        Ok(())
    }

    fn name(&self) -> &str {
        "blackfin timers"
    }

    fn tick(&mut self, ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
        let mut raised = RaisedIrqs::none();
        if self.running && self.loop_status.triggered.load(Ordering::Relaxed) {
            self.loop_status.triggered.store(false, Ordering::Relaxed);
            for enabled_timer in self.timers.enabled_timers() {
                // timer_went_off latches the proper peripheral and returns the core interrupt
                if let Some(irq) = self.timers.timer_went_off(ctx.memory, enabled_timer) {
                    raised.push(irq);
                }
            }
        }
        Ok(raised)
    }
}

/// Memory write hook for the timer registers.
///
/// Holds a clone of the shared [`TimerContainer`] so register writes mutate the same state the
/// peripheral ticks against.
struct TimerRegisterWriteHook {
    timers: Arc<TimerContainer>,
}

impl MemoryWriteHook for TimerRegisterWriteHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let timers = &self.timers;
        match address as u32 {
            sys::TIMER_ENABLE => timers.timer_enable(data[0]),
            sys::TIMER_DISABLE => timers.timer_disable(data[0]),

            sys::TIMER0_CONFIG | sys::TIMER1_CONFIG => {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(data);
                let data_u16 = u16::from_le_bytes(buf);
                match address as u32 {
                    sys::TIMER0_CONFIG => timers.timer_config(TimerId::Zero, data_u16),
                    sys::TIMER1_CONFIG => timers.timer_config(TimerId::One, data_u16),
                    _ => {
                        warn!("unhandled 16bit register write: 0x{address:X}")
                    }
                }
            }
            sys::TIMER0_PERIOD
            | sys::TIMER1_PERIOD
            | sys::TIMER0_WIDTH
            | sys::TIMER1_WIDTH
            | sys::TIMER_STATUS => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(data);
                let data_u32 = u32::from_le_bytes(buf);
                match address as u32 {
                    sys::TIMER0_PERIOD => timers.timer_period(TimerId::Zero, data_u32),
                    sys::TIMER1_PERIOD => timers.timer_period(TimerId::One, data_u32),
                    sys::TIMER0_WIDTH => timers.timer_width(TimerId::Zero, data_u32),
                    sys::TIMER1_WIDTH => timers.timer_width(TimerId::One, data_u32),
                    sys::TIMER_STATUS => timers.timer_status(data_u32),
                    _ => {
                        warn!("unhandled 16bit register write: 0x{address:X}")
                    }
                }
            }
            _ => warn!("unsupported address write to system interrupt registers: 0x{address:X}"),
        }
        Ok(())
    }
}
