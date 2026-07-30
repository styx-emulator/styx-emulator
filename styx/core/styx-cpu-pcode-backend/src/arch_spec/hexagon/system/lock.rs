// SPDX-License-Identifier: BSD-2-Clause
//! Shared logic for tlb/k0lock instructions.
//! See 11.9.2 "acquire hardware lock"

use std::str::FromStr;

use log::warn;
use styx_cpu_type::arch::hexagon::{register_fields::Syscfg, HexagonRegister};
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::Mmu,
};

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    HexagonPcodeBackend, PCodeStateChange,
};

use super::interrupt::HexagonInterruptType;

#[derive(Debug)]
pub enum HexagonLockType {
    K0,
    Tlb,
}

#[derive(Debug)]
pub struct HardwareLock {
    lock_type: HexagonLockType,
}
impl<T: CpuBackend> CallOtherCallback<T> for HardwareLock {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let syscfg = Syscfg::new_with_raw_value(
            cpu.read_register::<u32>(HexagonRegister::SysCfg)
                .with_context(|| "couldn't read Syscfg register")?,
        );

        let lock = match self.lock_type {
            HexagonLockType::K0 => syscfg.k0lock(),
            HexagonLockType::Tlb => syscfg.tlblock(),
        };

        // Already locked... according to hexagon QEMU in target/hexagon/op_helper.c,
        // must halt if double locked.
        //
        // TODO: queuing when multithread. When the thread is unlocked, we take the thread to unlock
        // and set its lock status to queued. Then the waiting thread is awoken.
        if lock {
            // Halting interrupt. According to qemu, this would be a double interrupt.
            Ok(PCodeStateChange::DelayedInterrupt(
                HexagonInterruptType::Halt as i32,
            ))
        } else {
            // The lock is acquired
            cpu.write_register(
                HexagonRegister::SysCfg,
                match self.lock_type {
                    HexagonLockType::K0 => syscfg.with_k0lock(true),
                    HexagonLockType::Tlb => syscfg.with_tlblock(true),
                }
                .raw_value(),
            )
            .with_context(|| "couldn't write syscfg")?;
            Ok(PCodeStateChange::Fallthrough)
        }
    }
}

#[derive(Debug)]
pub struct HardwareUnlock {
    lock_type: HexagonLockType,
}
impl<T: CpuBackend> CallOtherCallback<T> for HardwareUnlock {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let syscfg = Syscfg::new_with_raw_value(
            cpu.read_register::<u32>(HexagonRegister::SysCfg)
                .with_context(|| "couldn't read Syscfg register")?,
        );

        let lock = match self.lock_type {
            HexagonLockType::K0 => syscfg.k0lock(),
            HexagonLockType::Tlb => syscfg.tlblock(),
        };

        // Never had the lock
        if !lock {
            // Halting interrupt. According to qemu, this would be a double interrupt.
            warn!("{:?} never unlocked", self.lock_type);
            Ok(PCodeStateChange::Fallthrough)
        }
        // According to hexagon QEMU (hex-next quic qemu) in target/hexagon/op_helper.c,
        // we must use a round-robin method of choosing the next thread to get the lock.
        // Since we are single-threaded, we can just unlock.
        else {
            // The lock is released
            cpu.write_register(
                HexagonRegister::SysCfg,
                match self.lock_type {
                    HexagonLockType::K0 => syscfg.with_k0lock(false),
                    HexagonLockType::Tlb => syscfg.with_tlblock(false),
                }
                .raw_value(),
            )
            .with_context(|| "couldn't write syscfg")?;
            Ok(PCodeStateChange::Fallthrough)
        }
    }
}

pub fn add_lock_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlblock,
            HardwareLock {
                lock_type: HexagonLockType::Tlb,
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::K0lock,
            HardwareLock {
                lock_type: HexagonLockType::K0,
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbunlock,
            HardwareUnlock {
                lock_type: HexagonLockType::Tlb,
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::K0unlock,
            HardwareUnlock {
                lock_type: HexagonLockType::K0,
            },
        )
        .unwrap();
}
