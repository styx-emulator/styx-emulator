// SPDX-License-Identifier: BSD-2-Clause

//! QTimer for Hexagon. Information was acquired from
//! <https://github.com/quic/qemu>, branch hex-next, file
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
        log::{debug, info, trace},
        Context, EventControllerImpl, ExceptionNumber, Peripheral,
    },
};

use bitbybit::{bitenum, bitfield};

use crate::config::HexagonProcessorConfig;

/// Each "frame" is a 4k page (0x1000 bytes). The first frame contains
/// general config information. The registers in this frame are
/// documented in QTimerCNTCTLBaseFrame. Starting at the second page (0x1000),
/// there are (up to, and in our implementation case exactly) 8 separate
/// timers, each mapped to one frame. The registers for these frames are documented
/// in QTimerCNTCTLBaseNFrame. For QTimerCNTBaseNFrame, the 4-byte registers
/// starting at 0x40 offset from CNTCTL up to 0x5c allow us to set various access control
/// details for various registers in the CNTBaseN frame.
///
/// See Section D5.4 of the aforementioned ARM manual.
const CNT_ACR_START: u16 = 0x40u16;
const CNT_ACR_END: u16 = 0x5cu16;

const QTIMER_OFFSET: u64 = 0x20000;
const QTIMER_NUM_TIMERS: u64 = 8;

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

    /// Information that is only recieved during init() from the processor config.

    /// Base address of peripheral.
    qtimer_base: Option<u64>,
    /// What IRQ number to latch to on the L2Vic?
    irq: Option<ExceptionNumber>,
    pcycles_per_packet: Option<u64>,
    /// Frequency of the timer. At the end of 1 second, the
    /// timer value should go up by this much (if I understand
    /// it correctly). This is fixed by the hardware, seemingly.
    /// See D5.2.1.
    freq: Option<u32>,
    /// After how many pcycles should we tick the timer?
    /// Equal to QDSP_FREQ / QTIMER_FREQ
    pcycles_per_tick: Option<u64>,
}

/// This represents an individual timer.
/// See section D5.4. We may control each timer
/// with the control register, TimerValue register,
/// or CompareValue register. See B8.1.5 for this.
pub struct QTimerFrame {
    /// This is split into "lo" and "hi" in both the MMIO registers
    /// and actual utimerlo/utimerhi/timerlo/timerhi registers.
    counter: u64,

    /// Compare value register. This keeps track of the value set to compare against
    /// See table D5.5 for sizes. See B8.1.5.
    ///
    /// The timer value, according to "Operation of the TimerValue views of the timers"
    /// in B8.1.5, is equal to compare_value - (counter - offset). Since we don't
    /// have the virtual timer value seemingly, we can ignore the offset.
    compare_value: u64,
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
            compare_value: 0,
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
        qtimer_base: u64,
        timer_frequency: u32,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        proc.core.mmu.write_u32_le_phys_data(
            self.timers_frame_base(qtimer_base) + QTimerCNTBaseNFrame::CntFrq as u64,
            timer_frequency,
        )?;
        proc.core.mmu.write_u32_le_phys_data(
            self.timers_frame_base(qtimer_base) + QTimerCNTBaseNFrame::CntpCtl as u64,
            QTimerCNTPCTL::DEFAULT
                .with_enable(self.enabled)
                .with_imask(self.imask)
                .with_istatus(self.istatus)
                .raw_value(),
        )?;

        Ok(())
    }

    fn tick(
        &mut self,
        qtimer_base: u64,
        irq_base: ExceptionNumber,
        event_controller: &mut dyn EventControllerImpl,
        tick_amount: u64,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        // Using a read hook here would mean that when accessing memory
        // from a debugger, the hooks are not triggered. Instead, we keep
        // the value in physical memory in sync when the value needs to be updated.

        // Update the counter, setting memory in the process.
        self.increment_counter(qtimer_base, mmu, tick_amount)?;

        // Decrement TimerValue, setting memory in progress.
        self.write_timer_value(qtimer_base, mmu, tick_amount)?;

        trace!(
            "(tick inner) timer number is {} counter is {} compare value is {} enable is {} istatus is {}",
            self.frame_number,
            self.counter,
            self.compare_value,
            self.enabled,
            self.istatus
        );

        // Check for conditions (for if the timer should go off) being met and interrupt if so.
        // Don't latch an interrupt if one is already occurring.
        if (
            // CompareValue condition. Offset is zero. See B8.1.5 "Operation of the CompareValue views of the timers."
            // TimerValue condition should be equivalent, see "Operation of the TimerValue views of the timers" B8.1.5
            (self.counter - self.compare_value) as i64 >= 0)
            // Require the events to be enabled
            && self.enabled && !self.istatus
        {
            // When the timer condition is met, the status is set to one.
            // See D5.7.6 and the ISTATUS bit.
            self.istatus = true;

            // The frame number corresponds to the IRQ. We latch this.
            event_controller.latch(self.frame_number as ExceptionNumber + irq_base)?;
            debug!(
                "Ring ring, I am timer number {}, my and we latched {}.",
                self.frame_number,
                self.frame_number as ExceptionNumber + irq_base
            );
        }

        trace!("(tick inner) total ticks in counter {}", self.counter);
        Ok(())
    }

    fn increment_counter(
        &mut self,
        qtimer_base: u64,
        mmu: &mut Mmu,
        tick_amount: u64,
    ) -> Result<(), UnknownError> {
        // Update the counter, setting memory in the process.
        self.counter = self.counter.wrapping_add(tick_amount);

        let mut write_counter_to_mem = |lo_off: u64, hi_off: u64| -> Result<(), UnknownError> {
            mmu.write_u32_le_phys_data(
                self.timers_frame_base(qtimer_base) + lo_off,
                self.counter as u32,
            )?;
            mmu.write_u32_le_phys_data(
                self.timers_frame_base(qtimer_base) + hi_off,
                (self.counter >> 32) as u32,
            )?;
            Ok(())
        };

        // Physical counter
        write_counter_to_mem(
            QTimerCNTBaseNFrame::CntPctLo as u64,
            QTimerCNTBaseNFrame::CntPctHi as u64,
        )?;
        // Virtual counter
        write_counter_to_mem(
            QTimerCNTBaseNFrame::CntVctLo as u64,
            QTimerCNTBaseNFrame::CntVctHi as u64,
        )?;
        // TODO update registers.

        Ok(())
    }

    /// The timer value, according to "Operation of the TimerValue views of the timers"
    /// in B8.1.5, is equal to compare_value - (counter - offset). Since we don't
    /// have the virtual timer value seemingly, we can ignore the offset.
    fn timer_value(&mut self) -> u32 {
        (self.compare_value.wrapping_sub(self.counter)) as u32
    }

    /// NOTE WARN: this should not overwrite a previously set value for TimerValue!
    fn write_timer_value(
        &mut self,
        qtimer_base: u64,
        mmu: &mut Mmu,
        _tick_amount: u64,
    ) -> Result<(), UnknownError> {
        mmu.write_u32_le_phys_data(
            self.timers_frame_base(qtimer_base) + QTimerCNTBaseNFrame::CntpTval as u64,
            self.timer_value(),
        )?;

        Ok(())
    }

    /// Set the compare value, which is one of the ways to set
    /// a condition for when the timer should go off (see "Operation
    /// of the TimerValue views of the timers" in B8.1.5)
    fn set_compare_value(
        &mut self,
        qtimer_base: u64,
        mmu: &mut Mmu,
        new_value: u64,
    ) -> Result<(), UnknownError> {
        self.compare_value = new_value;

        mmu.write_u32_le_phys_data(
            self.timers_frame_base(qtimer_base) + QTimerCNTBaseNFrame::CntpCvalLo as u64,
            self.compare_value as u32,
        )?;
        mmu.write_u32_le_phys_data(
            self.timers_frame_base(qtimer_base) + QTimerCNTBaseNFrame::CntpCvalHi as u64,
            (self.compare_value >> 32) as u32,
        )?;

        Ok(())
    }
    /// Find the starting address of the individual timer frame which contains
    /// counters and Timer/CompareValue for this frame.
    ///
    /// Skips past the first frame, which is the base frame with control registers
    ///  for the entire peripheral.
    fn timers_frame_base(&self, qtimer_base: u64) -> u64 {
        // The first 0x1000 is used for more general access control configuration
        // The BaseN timer frames start at QTIMER_BASE + 0x1000 and are each size 0x1000.
        qtimer_base + (self.frame_number * 0x1000) + 0x1000
    }
}

impl Default for QTimer {
    fn default() -> Self {
        Self {
            // The DSP clock speed seemingly is equal to the number of pcycles.
            // QEMU has 1 packet equal to 3 pcycles, but it could also be 4 pcycles.
            // We will do 4 pcycles.
            //
            // Now, to find out how often to tick, we can take the DSP clock speed (
            // ?? representing number of pcycles per second) and divide it by the
            // timer frequency, which tells us how often to tick.
            total_pcycles: 0,
            pcycles_since_last_tick: 0,
            frame_secure: Default::default(),
            control_access_registers: Default::default(),
            timer_frames: array::from_fn(QTimerFrame::new),
            // Information that is only recieved during init() from the processor config.
            irq: None,
            pcycles_per_packet: None,
            pcycles_per_tick: None,
            freq: None,
            qtimer_base: None,
        }
    }
}

fn qtimer_mmio_read_hook(
    _proc: CoreHandle,
    _address: u64,
    _size: u32,
    _data: &mut [u8],
) -> Result<(), UnknownError> {
    // Nothing should happen as qtimer data is written to the backing memory.
    // unimplemented!("I read an mmio (:");

    Ok(())
}

fn qtimer_mmio_write_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let pc = proc.cpu.pc().unwrap();

    let timer_periph = proc.event_controller.peripherals.get::<QTimer>().unwrap();
    let qtimer_base = timer_periph
        .qtimer_base
        .expect("expected qtimer base to be filled in during peripheral init");
    let offset = address - qtimer_base;

    // CNTCTLBaseFrame, which configures the BaseN actual timers and such.
    if offset < 0x1000 {
        let qtimer_register = QTimerCNTCTLBaseFrame::new_with_raw_value(offset as u16);

        trace!(
            "accessed CNTCTL offset {offset} size {size} access_type WRITE data {data:x?} reg {qtimer_register:?} pc {pc:x}",
        );

        let data_u32 = u32::from_le_bytes(
            data.try_into()
                .with_context(|| "couldn't turn data into u32")?,
        );

        match qtimer_register {
            Ok(QTimerCNTCTLBaseFrame::CntFrq) => debug!(
                "the system set the frequency to {data_u32:x}, system frequency is {:x}",
                timer_periph
                    .freq
                    .expect("freq expected to be set during qtimer init")
            ),
            Ok(QTimerCNTCTLBaseFrame::CntNsar) => timer_periph.frame_secure = data_u32,
            // One of the "Control access control registers," between 0 and 6.
            Err(matched_off) => {
                if (CNT_ACR_START..=CNT_ACR_END).contains(&matched_off) {
                    // Get which control access register. Each register is 4 bytes
                    // TODO enforce secure acces to this based on the secure register stuff. (based on frame_secure?)
                    let cntacr_num = (matched_off - CNT_ACR_START) / 4;
                    debug!("writing to CNT ACR number {cntacr_num}");
                    timer_periph.control_access_registers[cntacr_num as usize] =
                        u32::from_le_bytes(data.try_into().with_context(|| {
                            "couldn't get control access register values as u32"
                        })?)
                }
            }
            _ => todo!(),
        }
    }
    // TODO: enforce access (based on frame_secure)
    // CNTBaseN frame. each frame is 0x1000 sized.
    else if (0x1000..0x1000 + (0x1000 * QTIMER_NUM_TIMERS)).contains(&offset) {
        let timer_offset = offset % 0x1000;
        let base_n = ((offset - 0x1000) / 0x1000) as usize;
        let qtimer_register = QTimerCNTBaseNFrame::new_with_raw_value(timer_offset as u16);

        let data_u32 = u32::from_le_bytes(
            data.try_into()
                .with_context(|| "couldn't turn data into u32")?,
        );

        trace!(
            "accessed base N {base_n} timer_offset {timer_offset} size {size} access_type WRITE data {data:x?} reg {qtimer_register:?} pc {pc:x}",
        );

        match qtimer_register {
            Ok(QTimerCNTBaseNFrame::CntpTval) => {
                // This is a timer value. This means B8.1.5 "Operation of the TimerValue views of the timers"
                // takes effect, so the value here is decremented at the frequency given until it reaches zero,
                // at which point an event (an interrupt) is triggered.
                debug!("the timer value (as opposed to compare value) is equal to {data_u32:x}. COUNTING DOWN.");

                // We must also set CompareValue. See the write effect on CompareValue for
                // "Operation of the TimerValue views of the timers" in B8.1.5.
                // the "as i64 as u64" sign extends the TimerValue. The Offset is 0.
                // See Reads within this section.
                //
                // Consistency: we _do_ have to set memory since this is a "side effect" of setting
                // the TimerValue.
                //
                // data_u32 is the starting timer value.
                timer_periph.timer_frames[base_n].set_compare_value(
                    qtimer_base,
                    proc.mmu,
                    timer_periph.timer_frames[base_n].counter + ((data_u32 as i64) as u64),
                )?;
            }
            // This is a compare value, so we wait for the timer count to reach the compare value, then trigger
            // the event (timer going off).
            // TODO: this requires testing.
            Ok(QTimerCNTBaseNFrame::CntpCvalLo | QTimerCNTBaseNFrame::CntpCvalHi) => {
                debug!(
                    "the compare value LO/HI (as opposed to timer value) is equal to {data_u32:x}, the timer register is {qtimer_register:?}"
                );
                let (new_data_replace, data_mask) = match qtimer_register {
                    Ok(QTimerCNTBaseNFrame::CntpCvalHi) => {
                        let hi_data = (data_u32 as u64) << 32;
                        (hi_data, 0x00000000ffffffff)
                    }
                    Ok(QTimerCNTBaseNFrame::CntpCvalLo) => {
                        // According to the write case in hex_timer_write for CNTP_CVAL_LO,
                        // writing this register should reset the timer.
                        timer_periph.timer_frames[base_n].istatus = false;
                        timer_periph.timer_frames[base_n].counter = 0;

                        let lo_data = data_u32 as u64;
                        (lo_data, 0xffffffff00000000)
                    }
                    _ => unreachable!(),
                };

                let new_compare_value = (timer_periph.timer_frames[base_n].compare_value
                    & data_mask)
                    | new_data_replace;
                debug!(
                    "writing new Compare Value as {new_compare_value:x}, old was {:x}",
                    timer_periph.timer_frames[base_n].compare_value
                );

                // Consistency: we want to keep the physical memory data in sync with the values here.
                // We don't have to set memory here, since during the memory write for this register
                // (the write that triggers this hook), the memory corresponding to this register will be set.
                timer_periph.timer_frames[base_n].set_compare_value(
                    qtimer_base,
                    proc.mmu,
                    new_compare_value,
                )?;
            }
            Ok(QTimerCNTBaseNFrame::CntpCtl) => {
                let register_value = QTimerCNTPCTL::new_with_raw_value(data_u32);
                debug!("the control value was set to {register_value:?}");

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
        // info!("We initialize the hook for cfgbase.");
        /*let cfgbase = proc
            .core
            .cpu
            .read_register::<u32>(HexagonRegister::CfgBase)
            .with_context(|| "couldn't read cfgbase")? as u64;
        self.update_setup_value_hooks(proc.core.cpu.as_mut(), QTimerHookName::CfgBase, cfgbase)?;*/

        let proc_cfg = proc.config.get::<HexagonProcessorConfig>().expect("You need to provide a hexagon process configuration in processor config to initialize qtimer");
        let timer_cfg = &proc_cfg.qtimer_config;

        let qtimer_base = proc_cfg.subsystem_base + QTIMER_OFFSET;

        self.pcycles_per_packet = Some(timer_cfg.pcycles_per_packet);
        self.pcycles_per_tick = Some((proc_cfg.dsp_freq / timer_cfg.timer_frequency) as u64);
        self.irq = Some(timer_cfg.irq);
        self.freq = Some(timer_cfg.timer_frequency);
        self.qtimer_base = Some(qtimer_base);

        for timer in self.timer_frames.iter_mut() {
            timer.init(proc, qtimer_base, timer_cfg.timer_frequency)?
        }

        proc.core
            .cpu
            .mem_write_hook(
                qtimer_base,
                qtimer_base + 0x1000 + (0x1000 * QTIMER_NUM_TIMERS),
                Box::new(qtimer_mmio_write_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for qtimer")?;

        proc.core
            .cpu
            .mem_read_hook(
                qtimer_base,
                qtimer_base + 0x1000 + (0x1000 * QTIMER_NUM_TIMERS),
                Box::new(qtimer_mmio_read_hook),
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
        info!("QTimer was reset.");
        Ok(())
    }

    fn irqs(&self) -> Vec<styx_core::prelude::ExceptionNumber> {
        vec![]
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
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
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

    fn tick(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        mmu: &mut styx_core::prelude::Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &styx_core::prelude::Delta,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        // The delta is the number of packets; there is a fixed number of
        // pcycles per packet. Basically the idae is that the pcycles since
        // last tick keeps track of pcycles, and the clock gets 1 tick
        // every "pcycles_per_tick."
        //
        self.pcycles_since_last_tick += delta.count
            * self
                .pcycles_per_packet
                .expect("Expected pcycles_per_packet set during initialization");
        self.total_pcycles += delta.count
            * self
                .pcycles_per_packet
                .expect("Expected pcycles_per_packet set during initialization");

        // As an example, if we have 10 pcycles per tick, and
        // the number of pcycles per packet is 4, then let's say that
        // the number of packets that ran from last time to now is 2.
        // For example, let the number of pcycles since last tick be 9.
        //
        // Now, we have 8 pcycles. In total we have 17 pcycles. We tick
        // once since the number of pcycles is > 17. Then, we set
        // the pcycles to 7 and wait till the pcycles goes up to past 10 again, then
        // tick, then continue.

        let pcycles_per_tick = self.pcycles_per_tick.expect("couldn't get pcycles_per_tick which should have been initialized in the qtimer init function");
        let timer_ticks = self.pcycles_since_last_tick / pcycles_per_tick;

        trace!(
            "TIMER tick: pcycles_since_last_tick {}, timer_ticks {}, pcycles_per_tick {}",
            self.pcycles_since_last_tick,
            timer_ticks,
            pcycles_per_tick,
        );

        if timer_ticks > 0 {
            for timer in self.timer_frames.iter_mut() {
                timer.tick(
                    self.qtimer_base
                        .expect("qtimer base expected to be set during qtimer init"),
                    self.irq.expect("IRQ expected to be set during qtimer init"),
                    event_controller,
                    timer_ticks,
                    mmu,
                )?;
            }

            // After ticking the qtimer, we remove the "pcycles" that were consumed by the tick
            // from this variable.
            let pcycles_per_tick = self.pcycles_per_tick.expect("couldn't get pcycles_per_tick which should have been initialized in the qtimer init function");
            self.pcycles_since_last_tick -= timer_ticks * pcycles_per_tick;
            trace!(
                "TIMERs ticked, now pcycles_since_last_tick is {}",
                self.pcycles_since_last_tick
            );
        }

        Ok(())
    }
}
