// SPDX-License-Identifier: BSD-2-Clause

//! QTimer for Hexagon. Information was acquired from
//! https://github.com/quic/qemu, branch hex-next, file
//! hw/timer/qct-qtimer.c.
//!
//! Also QEMU hexagon testing - standalone_systests/src/lock_timer_test.c
//!
//! Along with the "Generic Timer" documentation in the ArmV7A/ArmV7R architecture reference manual.

use std::{array, collections::HashMap};

use styx_core::{
    arch::{hexagon::HexagonRegister, RegisterValue},
    cpu::{CpuBackend, CpuBackendExt},
    errors::UnknownError,
    hooks::{CoreHandle, HookToken, StyxHook},
    prelude::{
        anyhow,
        log::{error, info, warn},
        ArchRegister, Context, Peripheral,
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

const QTIMER_DEFAULT_FREQ: u32 = 19200000;
const QDSP_CLOCK: u32 = 576000000;

/// D5.7.6 ARM manual
#[bitfield(u32, debug)]
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
    /// If a bit in this is set, then the nth timer at that bit
    /// is now accessible without secure. See D5.7.5 of the ARM manual.
    frame_secure: u32,
    control_access_registers: [u32; 7],
    timer_frames: [QTimerFrame; 7],
}

/// See D5.5 table for sizes.
#[derive(Default)]
pub enum QTimerConditionMode {
    TimerValue(u32),
    CompareValue(u64),
    #[default]
    None,
}

/// This represents an individual timer.
/// See section D5.4. We may control each timer
/// with the control register, TimerValue register,
/// or CompareValue register. See B8.1.5 for this.
#[derive(Default)]
pub struct QTimerFrame {
    /// This is split into "lo" and "hi" in both the MMIO registers
    /// and actual utimerlo/utimerhi/timerlo/timerhi registers.
    counter: u64,
    /// This is the condition mode. TimerValue goes down while
    /// QTimerConditionMode waits until the timer (minus offset if that eixsts)
    /// satisfies this value. Again see B8.1.5.
    condition_mode: QTimerConditionMode,
    /// Enabled or nah?
    enabled: bool,
    /// Event interrupt is masked?
    imask: bool,
    /// Was the condition for the timer (eg. from the condition mode) met?
    istatus: bool,
}

impl Default for QTimer {
    fn default() -> Self {
        Self {
            freq: QTIMER_DEFAULT_FREQ,
            frame_secure: Default::default(),
            control_access_registers: Default::default(),
            timer_frames: array::from_fn(|_| QTimerFrame::default()),
        }
    }
}

// First it writes offset 4 sz 4 CNTSR
// Then it writes offset 64 sz 4 CNTACR
// Then it writes offset 0 sz 4 CNTFRQ
fn qtimer_mmio_read_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let timer_periph = proc.event_controller.peripherals.get::<QTimer>().unwrap();

    error!(
        "accessed offset {} size {size} access_type READ data {data:x?}",
        address - QTIMER_BASE
    );

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
    else if offset >= 0x1000 && offset < 0x9000 {
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
                timer_periph.timer_frames[base_n].condition_mode =
                    QTimerConditionMode::TimerValue(data_u32);
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

/*fn cfg_subsys_base_hook(
    hook_name: QTimerHookName,
    proc: CoreHandle,
    new_val: u64,
) -> Result<(), UnknownError> {
    info!("hook, {:?} was set, new_val {:x}", hook_name, new_val);
    let timer_periph = proc.event_controller.peripherals.get::<QTimer>().unwrap();

    match hook_name {
        // If the subsystem base changed, the qtimer base changed.
        QTimerHookName::SubsystemBase => {
            let subsys_base = new_val << 16;
            let qtimer_base = subsys_base + QTIMER_OFFSET;

            timer_periph.update_setup_value_hooks(
                proc.cpu,
                QTimerHookName::SubsystemBase,
                subsys_base,
            )?;
            timer_periph.update_setup_value_hooks(
                proc.cpu,
                QTimerHookName::QTimerBase,
                qtimer_base,
            )?;
        }
        // If the config base changed, then the subsystem base could have also changed.
        QTimerHookName::CfgBase => {
            let cfg_base = new_val << 16;
            let subsys_base = proc
                .mmu
                .read_u32_le_phys_data(new_val + SUBSYSTEM_BASE)
                .with_context(|| "couldn't read subsys base")? as u64;

            timer_periph.update_setup_value_hooks(proc.cpu, QTimerHookName::CfgBase, cfg_base)?;
            timer_periph.update_setup_value_hooks(
                proc.cpu,
                QTimerHookName::SubsystemBase,
                subsys_base,
            )?;
        }
        QTimerHookName::QTimerBase => unreachable!(),
    }

    Ok(())
}

#[derive(Debug, Eq, Hash, Copy, Clone, PartialEq)]
enum QTimerHookName {
    SubsystemBase,
    CfgBase,
    // This is an offset of the subsystem base.
    QTimerBase,
}

impl QTimer {
    fn hook_value(&self, key: QTimerHookName) -> Option<u64> {
        self.qtimer_values.get(&key).copied()
    }
    fn update_setup_value_hooks(
        &mut self,
        cpu: &mut dyn CpuBackend,
        key: QTimerHookName,
        val: u64,
    ) -> Result<(), UnknownError> {
        self.qtimer_values.insert(key, val);

        if let Some(current_hooks) = self.qtimer_hooks.get_mut(&key) {
            // Step 1: delete le old hooks
            while let Some(hook) = current_hooks.pop() {
                cpu.delete_hook(hook)
                    .with_context(|| "couldn't delete hook")?;
            }
        }
        // Step 2: add our new hooks with new value
        let value = self
            .qtimer_values
            .get(&key)
            .with_context(|| "no value for key hook")?;
        let mut tokens = match key {
            QTimerHookName::SubsystemBase => vec![cpu
                .mem_write_hook(
                    *value,
                    *value + 4,
                    Box::new(
                        |core: CoreHandle,
                         _address: u64,
                         _size: u32,
                         value: &[u8]|
                         -> Result<(), UnknownError> {
                            cfg_subsys_base_hook(
                                QTimerHookName::SubsystemBase,
                                core,
                                u32::from_le_bytes(value.try_into().with_context(|| {
                                    "couldn't turn value to u32 for subsystem base"
                                })?) as u64,
                            )
                        },
                    ),
                )
                .with_context(|| "couldn't add subsystem base write hook")?],
            QTimerHookName::CfgBase => {
                info!("adding cfgbase hook");
                vec![cpu.add_hook(StyxHook::RegisterWrite(
                    HexagonRegister::CfgBase.into(),
                    Box::new(
                        |proc: CoreHandle,
                         _register: ArchRegister,
                         data: &RegisterValue|
                         -> Result<(), UnknownError> {
                            info!("had a cfg base update");
                            if let RegisterValue::u32(val) = data {
                                cfg_subsys_base_hook(QTimerHookName::CfgBase, proc, *val as u64)
                            } else {
                                Err(anyhow!(
                                    "The Hexagon cfgbase register update was not 32 bits"
                                ))
                            }
                        },
                    ),
                ))?]
            }

            QTimerHookName::QTimerBase => {
                vec![
                    // QTIMER_MEM_SIZE_BYTES is 0x1000, hence the addition
                    cpu.mem_write_hook(*value, *value + 0x1000, Box::new(qtimer_mmio_write_hook))
                        .with_context(|| "couldn't add MMIO hooks for qtimer")?,
                    cpu.mem_read_hook(*value, *value + 0x1000, Box::new(qtimer_mmio_read_hook))
                        .with_context(|| "couldn't add MMIO hooks for qtimer")?,
                ]
            }
        };

        match self.qtimer_hooks.get_mut(&key) {
            Some(vector) => vector.append(&mut tokens),
            None => {
                self.qtimer_hooks.insert(key, tokens);
            }
        }

        Ok(())
    }
}*/

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

        proc.core
            .cpu
            .mem_write_hook(
                QTIMER_BASE,
                QTIMER_BASE + 0x2000,
                Box::new(qtimer_mmio_write_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for qtimer")?;
        proc.core
            .cpu
            .mem_read_hook(
                QTIMER_BASE,
                QTIMER_BASE + 0x2000,
                Box::new(qtimer_mmio_read_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for qtimer")?;

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

    fn tick(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
        _delta: &styx_core::prelude::Delta,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        for timer in self.timer_frames.iter_mut() {
            // Only tick the enabled timers.
            if timer.enabled {}
        }

        Ok(())
    }
}
