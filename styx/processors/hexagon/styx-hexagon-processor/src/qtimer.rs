// SPDX-License-Identifier: BSD-2-Clause

//! QTimer for Hexagon. Information was acquired from
//! https://github.com/quic/qemu, branch hex-next, file
//! hw/timer/qct-qtimer.c.
//!
//! Also QEMU hexagon testing - standalone_systests/src/lock_timer_test.c
//!
//! Along with the "Generic Timer" documentation in the ArmV7A/ArmV7R architecture reference manual.

use std::array;

use styx_core::{
    errors::UnknownError,
    hooks::CoreHandle,
    memory::Mmu,
    prelude::{
        log::{error, info, trace},
        Context, Peripheral,
    },
};

use bitbybit::{bitenum, bitfield};

/// There are 8 separate timers, each mapped to a frame
/// aligned to 4k page size (0x1000). The 4-byte registers
/// starting at 0x40 offset from CNTCTL up to 0x5c allow us to
/// set various access control details for various
/// registers in the CNTBaseN frame. There are up to 8 frames,
/// which correspond to up to 8 actual timers.
///
/// See Section D5.4 of the aforementioned ARM manual.
const CNT_ACR_START: u16 = 0x40u16;
const CNT_ACR_END: u16 = 0x5cu16;

const SUBSYSTEM_BASE: u64 = 0xfc900000;

const QTIMER_BASE: u64 = SUBSYSTEM_BASE + QTIMER_OFFSET;
const QTIMER_OFFSET: u64 = 0x20000;

const QTIMER_FREQ: u32 = 19200000;
const QDSP_FREQ: u32 = 729600000;
const QTIMER_NUM_TIMERS: u64 = 8;

const PCYCLES_PER_PACKET: u64 = 4;

/// D5.7.6 ARM manual
#[bitfield(u32, default = 0x0, debug)]
pub struct QTimerCNTPCTL {
    #[bit(0, rw)]
    enable: bool,
    #[bit(1, rw)]
    imask: bool,
    #[bit(2, rw)]
    istatus: bool,
}

/// D5.6 ARM manual
#[derive(Debug)]
#[bitenum(u16, exhaustive = false)]
pub enum QTimerCNTCTLBaseFrame {
    /// Counter frequency register
    ///
    /// According to the manual, B4.1.21 Note,
    /// this doesn't actually set the frequency;
    /// the frequency seems to be hardcoded.
    /// However, this is set in order for software to
    /// read from to understand.
    CntFrq = 0x0,
    /// Counter non-secure reigster
    CntNsar = 0x4,
    /// Counter timer ID register
    CntTidr = 0x8,
    /// Counter access control register (0 to 6), 4 bytes each.
    /// CntacrStart = 0x40,
    /// CntacrEnd = 0x5c,
    Version = 0xfd0,
}

/// D5.5 ARM manual
/// pl1?? phys timer, see table b8-1
#[derive(Debug)]
#[bitenum(u16, exhaustive = false)]
pub enum QTimerCNTBaseNFrame {
    /// Physical count low registger
    CntPctLo = 0x0,
    /// Physical count hi register
    CntPctHi = 0x4,
    /// Virtual count low register
    CntVctLo = 0x8,
    /// Virtual count hi register
    CntVctHi = 0xc,
    /// Counter frequency register
    CntFrq = 0x10,
    /// Physical timer compare value register
    CntpCvalLo = 0x20,
    CntpCvalHi = 0x24,
    /// Physical timer value register
    /// NOTE: "After the timer condition is met, a read of the TimerValue register indicates the time since the condition was met."
    CntpTval = 0x28,
    /// Physical timer control register
    CntpCtl = 0x2c,
}

pub struct QTimer {
    /// Frequency of the timer. At the end of 1 second, the
    /// timer value should go up by this much (if I understand
    /// it correctly). This is fixed by the hardware, seemingly.
    /// See D5.2.1.
    freq: u32,
    /// After how many pcycles should we tick the timer?
    /// Equal to QDSP_FREQ / QTIMER_FREQ
    pcycles_per_tick: u64,
    /// Used to keep track of things.
    total_pcycles: u64,
    /// Used to keep track of pcycles until it is time to tick,
    /// then things are cleared
    pcycles_since_last_tick: u64,
    /// If a bit in this is set, then the nth timer at that bit
    /// is now accessible without secure. See D5.7.5 of the ARM manual.
    frame_secure: u32,
    control_access_registers: [u32; QTIMER_NUM_TIMERS as usize],
    timer_frames: [QTimerFrame; QTIMER_NUM_TIMERS as usize],
}

/// See D5.5 table for sizes.
#[derive(Default)]
pub enum QTimerConditionMode {
    TimerValue,
    CompareValue(u64),
    #[default]
    None,
}

/// This represents an individual timer.
/// See section D5.4. We may control each timer
/// with the control register, TimerValue register,
/// or CompareValue register. See B8.1.5 for this.
pub struct QTimerFrame {
    /// This is split into "lo" and "hi" in both the MMIO registers
    /// and actual utimerlo/utimerhi/timerlo/timerhi registers.
    counter: u64,
    /// This is the condition mode. TimerValue goes down while
    /// QTimerConditionMode waits until the timer (minus offset if that eixsts)
    /// satisfies this value. Again see B8.1.5.
    condition_mode: QTimerConditionMode,
    /// This is always being decremented, even without a condition.
    /// It will overflow when it starts at 0. This is explicitly a u32,
    /// D5.7.8.
    decrement_counter: u32,
    /// Enabled? This doesn't mean the timer doesn't stop counting down or up,
    /// it just means that the timer won't interrupt when the condition in
    /// condition_mode is met. (see D5.7.6)
    enabled: bool,
    /// Event interrupt is masked?
    imask: bool,
    /// Was the condition for the timer (eg. from the condition mode) met?
    istatus: bool,
    /// Frame number of the timer. Used for updating
    /// the lo/hi count
    frame_number: u64,
}

impl QTimerFrame {
    fn new(frame_number: usize) -> Self {
        Self {
            counter: 0,
            decrement_counter: 0,
            condition_mode: QTimerConditionMode::None,
            enabled: false,
            imask: false,
            istatus: true,
            frame_number: frame_number as u64,
        }
    }

    /// Write the frequency and physical timer control
    /// to memory here. We use init to set this up
    /// since this is the first point in the peripheral lifecycle
    /// that we can get access to the Mmu.
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        proc.core.mmu.write_u32_le_phys_data(
            self.frame_base() + QTimerCNTBaseNFrame::CntFrq as u64,
            QTIMER_FREQ,
        )?;
        proc.core.mmu.write_u32_le_phys_data(
            self.frame_base() + QTimerCNTBaseNFrame::CntpCtl as u64,
            QTimerCNTPCTL::DEFAULT
                .with_enable(self.enabled)
                .with_imask(self.imask)
                .with_istatus(self.istatus)
                .raw_value(),
        )?;

        Ok(())
    }

    fn tick(&mut self, tick_amount: u64, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // Tick all the timers!
        self.counter = self.counter.wrapping_add(tick_amount);
        // The SelfValue needs to be decremented always
        self.decrement_counter = self.decrement_counter.wrapping_sub(tick_amount as u32);

        // Check for conditions being met and interrupt if so.
        let irq = match self.condition_mode {
            // B8.1.5 "Operation of the TimerValue views of the timers"
            QTimerConditionMode::TimerValue if self.decrement_counter as i32 <= 0 => true,
            // B8.1.5 "Operation of the CompareValue views of the timers"
            // We have not implemented an offset.
            QTimerConditionMode::CompareValue(value) if (self.counter - value) as i64 >= 0 => true,
            _ => false,
        };

        // Update memory and TODO registers. Using a read hook here would mean that when accessing memory
        // from a debugger, the hooks are not triggered. For clarity, we split our write into lo and hi.

        // Physical counter
        self.write_counter(
            mmu,
            QTimerCNTBaseNFrame::CntPctLo as u64,
            QTimerCNTBaseNFrame::CntPctHi as u64,
        )?;
        // Virtual counter
        self.write_counter(
            mmu,
            QTimerCNTBaseNFrame::CntVctLo as u64,
            QTimerCNTBaseNFrame::CntVctHi as u64,
        )?;
        // TimerValue
        // NOTE WARN: this should not overwrite a previously set value for TimerValue!
        self.write_timervalue(mmu, QTimerCNTBaseNFrame::CntpTval as u64)?;

        // Latch interrupt or something
        // TODO: Pending l2vic implementation?
        if irq {
            todo!("Ring ring! The timer went off, but we haven't implemented that yet ):")
        }

        trace!("total ticks in counter {}", self.counter);
        Ok(())
    }

    fn write_counter(&self, mmu: &mut Mmu, lo_off: u64, hi_off: u64) -> Result<(), UnknownError> {
        mmu.write_u32_le_phys_data(self.frame_base() + lo_off, self.counter as u32)?;
        mmu.write_u32_le_phys_data(self.frame_base() + hi_off, (self.counter >> 32) as u32)?;

        Ok(())
    }
    fn write_timervalue(&self, mmu: &mut Mmu, off: u64) -> Result<(), UnknownError> {
        error!(
            "writing decrement counter as {}, frame {}",
            self.decrement_counter, self.frame_number
        );
        mmu.write_u32_le_phys_data(self.frame_base() + off, self.decrement_counter)?;

        Ok(())
    }

    /// Find the starting address of the individual timer frame which contains
    /// counters and Timer/CompareValue for this frame.
    fn frame_base(&self) -> u64 {
        // The first 0x1000 is used for more general access control configuration
        // The BaseN timer frames start at QTIMER_BASE + 0x1000 and are each size 0x1000.
        QTIMER_BASE + (self.frame_number * 0x1000) + 0x1000
    }
}

impl Default for QTimer {
    fn default() -> Self {
        Self {
            freq: QTIMER_FREQ,
            // The DSP clock speed seemingly is equal to the number of pcycles.
            // QEMU has 1 packet equal to 3 pcycles, but it could also be 4 pcycles.
            // We will do 4 pcycles.
            //
            // Now, to find out how often to tick, we can take the DSP clock speed (
            // ?? representing number of pcycles per second) and divide it by the
            // timer frequency, which tells us how often to tick.
            pcycles_per_tick: (QDSP_FREQ / QTIMER_FREQ) as u64,
            total_pcycles: 0,
            pcycles_since_last_tick: 0,
            frame_secure: Default::default(),
            control_access_registers: Default::default(),
            timer_frames: array::from_fn(|i| QTimerFrame::new(i)),
        }
    }
}

fn qtimer_mmio_write_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let pc = proc.cpu.pc().unwrap();

    let timer_periph = proc.event_controller.peripherals.get::<QTimer>().unwrap();
    let offset = address - QTIMER_BASE;

    // CNTCTLBaseFrame, which configures the BaseN actual timers and such.
    if offset < 0x1000 {
        let qtimer_register = QTimerCNTCTLBaseFrame::new_with_raw_value(offset as u16);

        error!(
            "accessed CNTCTL offset {} size {size} access_type WRITE data {data:x?} reg {:?} pc {:x}",
            offset, qtimer_register, pc
        );

        let data_u32 = u32::from_le_bytes(
            data.try_into()
                .with_context(|| "couldn't turn data into u32")?,
        );

        match qtimer_register {
            Ok(QTimerCNTCTLBaseFrame::CntFrq) => info!(
                "the system set the frequency to {data_u32:x}, system frequency is {:x}",
                timer_periph.freq
            ),
            Ok(QTimerCNTCTLBaseFrame::CntNsar) => timer_periph.frame_secure = data_u32,
            // One of the "Control access control registers," between 0 and 6.
            Err(matched_off) => {
                if matched_off >= CNT_ACR_START && matched_off <= CNT_ACR_END {
                    // Get which control access register. Each register is 4 bytes
                    // TODO enforce secure acces to this based on the secure register stuff.
                    let cntacr_num = (matched_off - CNT_ACR_START) / 4;
                    info!("writing to CNT ACR number {cntacr_num}");
                    timer_periph.control_access_registers[cntacr_num as usize] =
                        u32::from_le_bytes(data.try_into().with_context(|| {
                            "couldn't get control access register values as u32"
                        })?)
                }
            }
            _ => todo!(),
        }
    }
    // TODO: calculate which base N
    // TODO: enforce access
    // CNTBaseN frame. each frame is 0x1000 sized.
    else if offset >= 0x1000 && offset < 0x1000 + (0x1000 * QTIMER_NUM_TIMERS) {
        let offset = offset % 0x1000;
        let base_n = (offset / 0x1000) as usize;
        let qtimer_register = QTimerCNTBaseNFrame::new_with_raw_value(offset as u16);

        let data_u32 = u32::from_le_bytes(
            data.try_into()
                .with_context(|| "couldn't turn data into u32")?,
        );

        error!(
            "accessed base N offset {} size {size} access_type WRITE data {data:x?} reg {:?} pc {:x}",
            offset, qtimer_register, pc
        );

        match qtimer_register {
            Ok(QTimerCNTBaseNFrame::CntpTval) => {
                // This is a timer value. This means B8.1.5 "Operation of the TimerValue views of the timers"
                // takes effect, so the value here is decremented at the frequency given until it reaches zero,
                // at which point an event (an interrupt) is triggered.
                info!("the timer value (as opposed to compare value) is equal to {data_u32:x}. COUNTING DOWN.");

                // Now we must start this timer with the frequency that was set.
                timer_periph.timer_frames[base_n].condition_mode = QTimerConditionMode::TimerValue;
                timer_periph.timer_frames[base_n].decrement_counter = data_u32;
            }
            // This is a compare value, so we basically go up until we hit this and trigger
            // the event at that point.
            Ok(QTimerCNTBaseNFrame::CntpCvalLo | QTimerCNTBaseNFrame::CntpCvalHi) => {
                info!(
                    "the compare value LO/HI (as opposed to timer value) is equal to {data_u32:x}"
                );
                let (new_data_shifted, new_data_replace) = match qtimer_register {
                    Ok(QTimerCNTBaseNFrame::CntPctHi) => {
                        let hi_data = (data_u32 as u64) << 32;
                        (hi_data, hi_data | 0x0000ffff)
                    }
                    Ok(QTimerCNTBaseNFrame::CntPctLo) => {
                        let lo_data = data_u32 as u64;
                        (lo_data, lo_data | 0xffff0000)
                    }
                    _ => unreachable!(),
                };
                timer_periph.timer_frames[base_n].condition_mode =
                    match timer_periph.timer_frames[base_n].condition_mode {
                        // Just set the lower bits (or higher bits).
                        QTimerConditionMode::CompareValue(old_value) => {
                            QTimerConditionMode::CompareValue(old_value & new_data_replace)
                        }
                        _ => QTimerConditionMode::CompareValue(new_data_shifted),
                    };
            }
            Ok(QTimerCNTBaseNFrame::CntpCtl) => {
                let register_value = QTimerCNTPCTL::new_with_raw_value(data_u32);
                info!("the control value was set to {:?}", register_value);

                timer_periph.timer_frames[base_n].enabled = register_value.enable();
                timer_periph.timer_frames[base_n].imask = register_value.imask();
                timer_periph.timer_frames[base_n].istatus = register_value.istatus();
            }
            _ => todo!(),
        }
    }

    Ok(())
}

impl Peripheral for QTimer {
    fn name(&self) -> &str {
        "Qualcomm timer"
    }

    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        // set a hook on cfgbase
        //
        // when cfgbase is modified, set a hook on the subsystem
        // base,
        //
        // when the subsystem base is modified, we now have the qtimer base,
        // set a hook for that.
        //
        // this seems excessively complicated..
        // but this is what we must do.
        // see SIU in powerquicc
        // just have a cfgbase handle here
        info!("We initialize the hook for cfgbase.");
        /*let cfgbase = proc
            .core
            .cpu
            .read_register::<u32>(HexagonRegister::CfgBase)
            .with_context(|| "couldn't read cfgbase")? as u64;
        self.update_setup_value_hooks(proc.core.cpu.as_mut(), QTimerHookName::CfgBase, cfgbase)?;*/

        for timer in self.timer_frames.iter_mut() {
            timer.init(proc)?
        }

        proc.core
            .cpu
            .mem_write_hook(
                QTIMER_BASE,
                QTIMER_BASE + 0x1000 + (0x1000 * QTIMER_NUM_TIMERS),
                Box::new(qtimer_mmio_write_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for qtimer")?;

        info!("QTimer initialized.");

        Ok(())
    }

    fn reset(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        info!("the qtimer was reset");
        Ok(())
    }

    fn irqs(&self) -> Vec<styx_core::prelude::ExceptionNumber> {
        std::vec![]
    }

    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
        _irqn: styx_core::prelude::ExceptionNumber,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        Ok(())
    }

    fn on_processor_start(
        &mut self,
        cpu: &mut dyn styx_core::prelude::CpuBackend,
        mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        Ok(())
    }

    // WARN: The tick doesn't work when you use a debugger.
    fn tick(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
        delta: &styx_core::prelude::Delta,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        self.pcycles_since_last_tick += delta.count * PCYCLES_PER_PACKET;
        self.total_pcycles += delta.count * PCYCLES_PER_PACKET;

        // As an example, if we have 10 pcycles per tick, and
        // the number of pcycles per packet is 4, then let's say that
        // the number of packets that ran from last time to now is 2.
        // For example, let the number of pcycles since last tick be 9.
        //
        // Now, we have 8 pcycles. In total we have 17 pcycles. We tick
        // once since the number of pcycles is > 17. Then, we set
        // the pcycles to 7 and wait till the pcycles goes up to past 10 again, then
        // tick, then continue.

        let timer_ticks = self.pcycles_since_last_tick / self.pcycles_per_tick;

        trace!(
            "TIMER tick: pcycles_since_last_tick {}, timer_ticks {}, pcycles_per_tick {}",
            self.pcycles_since_last_tick,
            timer_ticks,
            self.pcycles_per_tick,
        );

        if timer_ticks > 0 {
            for timer in self.timer_frames.iter_mut() {
                timer.tick(timer_ticks, mmu)?;
            }

            // Remove these many ticks from the current pcycles since last tick
            self.pcycles_since_last_tick -= timer_ticks * self.pcycles_per_tick;
            trace!(
                "TIMERs ticked, now pcycles_since_last_tick is {}",
                self.pcycles_since_last_tick
            );
        }

        Ok(())
    }
}
