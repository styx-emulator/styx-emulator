// SPDX-License-Identifier: BSD-2-Clause
mod timer;

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use derivative::Derivative;
use styx_core::prelude::*;
use timer::*;
use tokio_stream::StreamExt;
use tokio_timerfd::Interval;
use tracing::{debug, warn};

use styx_blackfin_sys::bf512 as sys;

use crate::core_event_controller::SicHandle;

#[derive(Clone, Default)]
pub struct TimerLoopStatus {
    triggered: Arc<AtomicBool>,
}

#[derive(Derivative)]
pub struct Timers {
    timers: TimerContainer,
    loop_status: TimerLoopStatus,
    running: bool,
}
async fn timer_loop(status: TimerLoopStatus) {
    let mut interval = Interval::new_interval(Duration::from_millis(100)).unwrap();
    loop {
        // sleep for our sleep time
        interval.next().await.unwrap().unwrap();
        status.triggered.store(true, Ordering::Relaxed);
    }
}

impl Timers {
    pub fn new(system: SicHandle) -> Self {
        Self {
            timers: TimerContainer::new(system),
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

        proc.core.cpu.mem_write_hook(
            sys::TIMER0_CONFIG as u64,
            sys::TIMER_STATUS as u64,
            Box::new(timer_register_write_hook),
        )?;

        Ok(())
    }

    fn name(&self) -> &str {
        "blackfin timers"
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        ev: &mut dyn EventControllerImpl,
        _delta: &styx_core::prelude::Delta,
    ) -> Result<(), UnknownError> {
        if self.running && self.loop_status.triggered.load(Ordering::Relaxed) {
            self.loop_status.triggered.store(false, Ordering::Relaxed);
            for enabled_timer in self.timers.enabled_timers() {
                // timer_went_off will latch proper peripheral
                self.timers.timer_went_off(mmu, ev, enabled_timer);
            }
        }
        Ok(())
    }
}

fn timer_register_write_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let timers = proc.event_controller.peripherals.get_expect::<Timers>()?;

    match address as u32 {
        sys::TIMER_ENABLE => timers.timers.timer_enable(data[0]),
        sys::TIMER_DISABLE => timers.timers.timer_disable(data[0]),

        sys::TIMER0_CONFIG | sys::TIMER1_CONFIG => {
            let mut buf = [0u8; 2];
            buf.copy_from_slice(data);
            let data_u16 = u16::from_le_bytes(buf);
            match address as u32 {
                sys::TIMER0_CONFIG => timers.timers.timer_config(TimerId::Zero, data_u16),
                sys::TIMER1_CONFIG => timers.timers.timer_config(TimerId::One, data_u16),
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
                sys::TIMER0_PERIOD => timers.timers.timer_period(TimerId::Zero, data_u32),
                sys::TIMER1_PERIOD => timers.timers.timer_period(TimerId::One, data_u32),
                sys::TIMER0_WIDTH => timers.timers.timer_width(TimerId::Zero, data_u32),
                sys::TIMER1_WIDTH => timers.timers.timer_width(TimerId::One, data_u32),
                sys::TIMER_STATUS => timers.timers.timer_status(data_u32),
                _ => {
                    warn!("unhandled 16bit register write: 0x{address:X}")
                }
            }
        }
        _ => warn!("unsupported address write to system interrupt registers: 0x{address:X}"),
    }
    Ok(())
}
