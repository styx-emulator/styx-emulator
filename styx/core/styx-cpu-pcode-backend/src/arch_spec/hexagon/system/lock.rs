// SPDX-License-Identifier: BSD-2-Clause
//! Shared logic for tlb/k0lock instructions.
//! See 11.9.2 "acquire hardware lock"

use std::{str::FromStr, sync::Mutex};

use log::{debug, info, warn};
use smallvec::smallvec;
use smallvec::SmallVec;
use styx_cpu_type::arch::hexagon::{
    register_fields::Syscfg, GlobalHexagonRegister, HexagonRegister,
};
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::Mmu,
};
use styx_sync::lazy_static;

// TODO: hexagon max threads
lazy_static! {
    static ref LOCK_STATE: Mutex<SmallVec<[HexagonLockState; 16]>> =
        Mutex::new(smallvec![HexagonLockState::Unlocked; 16]);
}

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

/// QEMU target/hexagon/op_helper.c I think.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HexagonLockState {
    Unlocked,
    LockHeld,
    Queued,
    Waiting,
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
            cpu.read_register::<u32>(GlobalHexagonRegister::SysCfg)
                .with_context(|| "couldn't read Syscfg register")?,
        );

        let lock = match self.lock_type {
            HexagonLockType::K0 => syscfg.k0lock(),
            HexagonLockType::Tlb => syscfg.tlblock(),
        };

        let htid = cpu
            .read_register::<u32>(HexagonRegister::Htid)
            .with_context(|| "couldn't read htid register")?;

        let lock_state_this_thread = {
            let lock_state = LOCK_STATE.lock().unwrap();
            lock_state[htid as usize]
        };

        let mut give_lock = || -> Result<PCodeStateChange, CallOtherHandleError> {
            let mut lock_state = LOCK_STATE.lock().unwrap();

            // The lock is acquired
            cpu.write_register(
                GlobalHexagonRegister::SysCfg,
                match self.lock_type {
                    HexagonLockType::K0 => syscfg.with_k0lock(true),
                    HexagonLockType::Tlb => syscfg.with_tlblock(true),
                }
                .raw_value(),
            )
            .with_context(|| "couldn't write syscfg")?;

            lock_state[htid as usize] = HexagonLockState::LockHeld;
            Ok(PCodeStateChange::Fallthrough)
        };

        // Already locked... according to hexagon QEMU in target/hexagon/op_helper.c,
        // must halt if double locked.
        //
        // TODO: queuing when multithread. When the thread is unlocked, we take the thread to unlock
        // and set its lock status to queued. Then the waiting thread is awoken.
        if lock {
            match lock_state_this_thread {
                HexagonLockState::LockHeld => {
                    // Halting interrupt. According to qemu, the same thread that holds the lock locking itself
                    //  would be a double interrupt.
                    warn!("htid {htid} trttried to lock twice");
                    Ok(PCodeStateChange::DelayedInterrupt(
                        HexagonInterruptType::Halt as i32,
                    ))
                }
                // We need to queue the lock.
                HexagonLockState::Unlocked => {
                    let mut lock_state = LOCK_STATE.lock().unwrap();
                    lock_state[htid as usize] = HexagonLockState::Waiting;

                    info!("lock held but {htid} wants it, halting {htid} till lock released");

                    Ok(PCodeStateChange::DelayedInterrupt(
                        HexagonInterruptType::Halt as i32,
                    ))
                }
                // If we are running the instruction with this, then we
                // need to give it the lock now.
                HexagonLockState::Queued => {
                    debug!("lock was held but {htid} was queued, giving lock to thread {htid}");
                    give_lock()
                }
                _ => unreachable!(),
            }
        }
        // No one else
        else {
            debug!("lock not held by anyone, giving lock to thread {htid}");
            give_lock()
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
        ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let syscfg = Syscfg::new_with_raw_value(
            cpu.read_register::<u32>(GlobalHexagonRegister::SysCfg)
                .with_context(|| "couldn't read Syscfg register")?,
        );

        let lock = match self.lock_type {
            HexagonLockType::K0 => syscfg.k0lock(),
            HexagonLockType::Tlb => syscfg.tlblock(),
        };
        let htid = cpu
            .read_register::<u32>(HexagonRegister::Htid)
            .with_context(|| "couldn't read htid register")?;

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
            let mut lock_state = LOCK_STATE.lock().unwrap();

            if lock_state[htid as usize] != HexagonLockState::LockHeld {
                warn!("htid {htid} tried to unlock a lock that is not held by them!!");
                Ok(PCodeStateChange::Fallthrough)
            } else {
                // The lock is released
                cpu.write_register(
                    GlobalHexagonRegister::SysCfg,
                    match self.lock_type {
                        HexagonLockType::K0 => syscfg.with_k0lock(false),
                        HexagonLockType::Tlb => syscfg.with_tlblock(false),
                    }
                    .raw_value(),
                )
                .with_context(|| "couldn't write syscfg")?;

                // Now figure out if anyone else is getting the lock.
                for i in 0..lock_state.len() {
                    // Adjust
                    let i = (htid as usize + i) % lock_state.len();

                    if let HexagonLockState::Waiting = lock_state[i] {
                        // Give them the lock
                        let syscfg = Syscfg::new_with_raw_value(
                            cpu.read_register::<u32>(GlobalHexagonRegister::SysCfg)
                                .with_context(|| "couldn't read syscfg")?,
                        );

                        cpu.write_register(
                            GlobalHexagonRegister::SysCfg,
                            match self.lock_type {
                                HexagonLockType::K0 => syscfg.with_k0lock(true),
                                HexagonLockType::Tlb => syscfg.with_tlblock(true),
                            }
                            .raw_value(),
                        )
                        .with_context(|| "couldn't write syscfg")?;

                        lock_state[i] = HexagonLockState::Queued;
                        unimplemented!("unimpl lowkey");

                        // ev.execute_to(i, HexagonInterruptType::K0Lock);
                        // ipend check that QEMU does
                    }
                }

                Ok(PCodeStateChange::Fallthrough)
            }
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
