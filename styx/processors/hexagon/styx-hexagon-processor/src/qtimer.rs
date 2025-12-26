// SPDX-License-Identifier: BSD-2-Clause

//! QTimer for Hexagon. Information was acquired from
//! https://github.com/quic/qemu, branch hex-next, file
//! hw/timer/qct-qtimer.c.
//!
//! Also QEMU hexagon testing - standalone_systests/src/lock_timer_test.c
//!
//! Along with the "Generic Timer" documentation in the ArmV7A/ArmV7R architecture reference manual.

use std::collections::HashMap;

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
use styx_peripherals::clock::Tick;

use crate::read_cfgtable_field;
use bitbybit::bitenum;

const CNT_ACR_START: u16 = 0x40u16;
const CNT_ACR_END: u16 = 0x5cu16;
const QTIMER_OFFSET: u64 = 0x20000;
const SUBSYSTEM_BASE: u64 = 0xfc900000;
const QTIMER_BASE: u64 = SUBSYSTEM_BASE + QTIMER_OFFSET;

#[derive(Debug)]
#[bitenum(u16, exhaustive = false)]
pub enum QTimerRegisters {
    // Counter frequency register
    CntFrq = 0x0,
    // Counter non-secure reigster
    CntSr = 0x4,
    // Counter timer ID register
    CntTid = 0x8,
    // Counter access control register (0 to 6), 4 bytes each.
    // CntacrStart = 0x40,
    // CntacrEnd = 0x5c,
    Version = 0xfd0,
}

#[derive(Default)]
pub struct QTimer {
    freq: u32,
    secure: u32,
    physical_counter: u64,
    control: u32,
    counter_control: u32,
    control_pl0_acr: u32,
    control_access_registers: [u32; 7],
    limit: u64,
    interrupt_level: u32,
    // qtimer_hooks: HashMap<QTimerHookName, Vec<HookToken>>,
    // qtimer_values: HashMap<QTimerHookName, u64>,
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
    let qtimer_register = QTimerRegisters::new_with_raw_value(offset as u16);

    error!(
        "accessed offset {} size {size} access_type WRITE data {data:x?} reg {:?} pc {:x}",
        offset, qtimer_register, pc
    );

    match qtimer_register {
        Ok(QTimerRegisters::CntFrq) => {
            timer_periph.freq = u32::from_le_bytes(
                data.try_into()
                    .with_context(|| "couldn't turn freq write data into u32")?,
            )
        }
        Ok(QTimerRegisters::CntSr) => {
            timer_periph.secure = u32::from_le_bytes(
                data.try_into()
                    .with_context(|| "couldn't turn secure write data into u32")?,
            )
        }
        // One of the "Control access control registers," between 0 and 6.
        Err(matched_off) => {
            if matched_off >= CNT_ACR_START && matched_off <= CNT_ACR_END {
                // Get which control access register. Each register is 4 bytes
                // TODO enforce secure acces to this based on the secure register stuff.
                let cntacr_num = (matched_off - CNT_ACR_START) / 4;
                info!("writing to CNT ACR number {cntacr_num}");
                timer_periph.control_access_registers[cntacr_num as usize] = u32::from_le_bytes(
                    data.try_into()
                        .with_context(|| "couldn't get control access register values as u32")?,
                )
            }
        }
        _ => todo!(),
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
        //
        // see SIUUUUUU in powerquicky
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
                QTIMER_BASE + 0x1000,
                Box::new(qtimer_mmio_write_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for qtimer")?;
        proc.core
            .cpu
            .mem_read_hook(
                QTIMER_BASE,
                QTIMER_BASE + 0x1000,
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
        Ok(())
    }
}
