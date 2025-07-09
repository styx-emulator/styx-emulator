// SPDX-License-Identifier: BSD-2-Clause
use crate::{CPUMode, Nvic, BUSFAULT_IRQN, MEMMANAGE_IRQN, SVCALL_IRQN, USAGEFAULT_IRQN};
use styx_core::prelude::*;
use styx_core::{cpu::arch::arm::ArmRegister, errors::UnknownError};
use tracing::{debug, trace, warn};

const NMI_PENDING: u32 = 1 << 31;
const PENDSV_PENDING: u32 = 1 << 28;
const SYSTICK_PENDING: u32 = 1 << 26;
const NMI_IRQN: ExceptionNumber = -14;
const PENDSV_IRQN: ExceptionNumber = -2;
const SYSTICK_IRQN: ExceptionNumber = -1;
const NVIC_ICSR_ADDRESS: u32 = 0xE000ED04;

/// This value marks the start of the special exception return values
const EXN_RETURN_BLOCK: u64 = 0xFFFF_FF00;

/// This performs actions based on the bits written to the ICSR
pub fn nvic_icsr_write_callback(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let icsr = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let nmi_set: bool = (icsr & NMI_PENDING) > 0;
    let pendsv_set: bool = (icsr & PENDSV_PENDING) > 0;
    let systick_set: bool = (icsr & SYSTICK_PENDING) > 0;

    if nmi_set {
        trace!("Triggering latch NMI_IRQN");
        proc.event_controller.latch(NMI_IRQN)?;
    }

    if pendsv_set {
        trace!("Triggering latch PENDSV_IRQN");
        proc.event_controller.latch(PENDSV_IRQN)?;
    }

    if systick_set {
        trace!("Triggering latch SYSTICK_IRQN");
        proc.event_controller.latch(SYSTICK_IRQN)?;
    }

    // we've handled it behind the scenes, clear the "set PendSV" bit
    let icsr = icsr & !(PENDSV_PENDING | SYSTICK_PENDING | NMI_PENDING);
    proc.mmu.data().write(NVIC_ICSR_ADDRESS).le().value(icsr)?;
    Ok(())
}

pub fn vtor_write_callback(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let vtor: u32 = u32::from_le_bytes(data[0..4].try_into().unwrap());

    debug!(
        "vtor set to: {}, address=0x{:08x}, size={}, data={:?}, pc=0x{:08x}",
        vtor,
        _address,
        _size,
        data,
        proc.cpu.pc().unwrap()
    );

    let nvic = proc.event_controller.get_impl::<Nvic>()?;

    nvic.set_vto(vtor);
    Ok(())
}

pub fn ccr_write_hook(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let nvic = proc.event_controller.get_impl::<Nvic>()?;
    let ccr: u32 = u32::from_le_bytes(data[0..4].try_into().unwrap());

    let mut flags = nvic.flags.lock().unwrap();

    flags.ccr_stkalign = ccr & (1 << 9) > 0;
    flags.ccr_nonbasethrdena = ccr & 1 > 0;
    Ok(())
}

// Exception return modes
const RET_HANDLER_MODE_W_MSP: u64 = 0x1;
const RET_THREAD_MODE_W_MSP: u64 = 0x9;
const RET_THREAD_MODE_W_PSP: u64 = 0xD;

/// Handles the return from an exception for the ARM Cortex-M architecture,
/// emulating the behavior of returning from an ISR (Interrupt Service Routine)
///
/// This roughly follows this list of steps:
/// 1. Check if we are currently in an ISR, if not, leave
/// 2. Get the current internal flags and hold th
/// 3. ensure the IPSR state matches the NVIC state
/// 4. Calculate the proper return address and return mode
///
/// NOTE: Locks `nvic.cpu_mode` `nvic.flags` and `nvic.interrupts`
pub fn return_from_exception(proc: CoreHandle) -> Result<(), UnknownError> {
    let nvic = proc.event_controller.get_impl::<Nvic>()?;
    // If we aren't currently in an ISR, then ignore the special values
    if *nvic.cpu_mode.read().unwrap() == CPUMode::Thread {
        return Err(anyhow!(
            "nvic return from exception but not currently in ISR"
        ));
    }

    let mut flags = nvic.flags.lock().unwrap();

    // integrity checks
    let ipsr = proc.cpu.read_register::<u32>(ArmRegister::Ipsr).unwrap();

    // get returning exception number
    let returning_irqn = (ipsr & 0x1FF) as i32 - 16;
    nvic.current_irqn = Some(returning_irqn);

    // assert that exception number being returned from is currently active
    assert!(
        nvic.check_interrupt_active(returning_irqn),
        "attempting to return from an inactive exception ({returning_irqn})"
    );

    let mut frame_ptr: ArmRegister = ArmRegister::Msp;

    // the EXC_RETURN value is the return address when jumping back,
    // because we are in THUMB mode (ARM Cortex-M), we must make the address
    // end with a 1 bit to ensure we are in THUMB mode
    let exc_return = proc.cpu.pc().unwrap() | 1;

    // This switch performs actions based on the EXC_RETURN value,
    // which is documented in the [`Nvic`] module documentation.
    match exc_return & 0xF {
        // return to handler mode w/ main stack
        RET_HANDLER_MODE_W_MSP => {
            // frameptr = msp
            *nvic.cpu_mode.write().unwrap() = CPUMode::Handler;
            flags.ctl_spsel = false;
        }
        // return to thread mode w/ main stack
        RET_THREAD_MODE_W_MSP => {
            // frameptr = msp
            *nvic.cpu_mode.write().unwrap() = CPUMode::Thread;
            flags.ctl_spsel = false;
        }
        // return to thread mode w/ process stack
        RET_THREAD_MODE_W_PSP => {
            frame_ptr = ArmRegister::Psp;
            *nvic.cpu_mode.write().unwrap() = CPUMode::Thread;
            flags.ctl_spsel = true;
        }
        _ => {
            panic!("Invalid EXC_RETURN value: 0x{:X}", exc_return);
        }
    }

    std::mem::drop(flags);

    // handle the special case for the NMI interrupt
    if returning_irqn != NMI_IRQN {
        // Returning from any exception except NMI clears FAULTMASK to 0
        proc.cpu
            .write_register(ArmRegister::Faultmask, 0_u32)
            .unwrap();
    }

    //
    // now we update the styx-level state and call the appropriate hooks
    //
    nvic.deactivate_current_interrupt(returning_irqn);
    nvic.interrupt_complete();

    // pop the exception handler stack to return to the target program
    // execution context
    let frame_ptr_value = proc.cpu.read_register::<u32>(frame_ptr).unwrap();
    nvic.pop_stack(
        proc.cpu,
        proc.mmu,
        frame_ptr_value,
        exc_return as u32,
        returning_irqn,
    );

    proc.event_controller.finish_interrupt(proc.cpu, proc.mmu);

    debug!(
        "Returning from exception IRQ_{returning_irqn} -> 0x{:08x}",
        proc.cpu.pc().unwrap()
    );
    Ok(())
}

pub fn fpccr_w_hook(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let nvic = proc.event_controller.get_impl::<Nvic>()?;
    let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let lspen = val & (1 << 30) > 0;
    let lspact = val & 1 > 0;

    let mut flags = nvic.flags.lock().unwrap();

    flags.fp_lspen = lspen;
    flags.fp_lspact = lspact;
    Ok(())
}

const UNICORN_EXCP_SWI: i32 = 2;
const UNICORN_EXCP_PREFETCH_ABORT: i32 = 3;
const UNICORN_EXCP_EXCEPTION_EXIT: i32 = 8;

/// the jank workaround to catch when the special EXC_RETURN values (0xFFFFFF**) get written to the PC.
pub fn interrupt_hook(proc: CoreHandle, intno: i32) -> Result<(), UnknownError> {
    debug!(
        "caught interrupt: {intno}, pc: 0x{:x}",
        proc.cpu.pc().unwrap()
    );

    match intno {
        UNICORN_EXCP_SWI => {
            // swi
            trace!("Got an SVC interrupt, executing through event controller.");

            // system call executes interrupt immediately
            proc.event_controller
                .execute(SVCALL_IRQN, proc.cpu, proc.mmu)?;
        }
        UNICORN_EXCP_PREFETCH_ABORT => {
            // prefetch abort
            let pc = proc.cpu.pc().unwrap();
            if pc >= EXN_RETURN_BLOCK {
                return_from_exception(proc)?;
            } else {
                // panic because this is not a recoverable cpu state
                // TODO: change this to a debug once we get prefetch hooks
                warn!("unhandled prefetch abort: 0x{:x}", pc);
            }
        }
        SVCALL_IRQN => {
            trace!("Got an SVC interrupt, executing through event controller.");

            // system call executes interrupt immediately
            proc.event_controller
                .execute(SVCALL_IRQN, proc.cpu, proc.mmu)?;
        }
        UNICORN_EXCP_EXCEPTION_EXIT => {
            let pc = proc.cpu.pc()?;
            if pc >= EXN_RETURN_BLOCK {
                return_from_exception(proc)?;
            } else {
                warn!("unhandled EXCP_EXCEPTION_EXIT: 0x{:x}", pc);
            }
        }
        _ => {
            warn!("unhandled interrupt: {intno}");
        }
    }
    Ok(())
}

/// Returns a vec containing the indices of set bits in bytes
#[inline]
fn get_set_bits(bytes: &[u8]) -> Vec<u32> {
    let mut res = vec![];

    for (idx, byte) in bytes.iter().enumerate() {
        let mut v = *byte;
        while v != 0 {
            let index = v.trailing_zeros();
            res.push(index + (idx * 8) as u32);
            v &= !(1 << index);
        }
    }

    res
}

const SHPR_BASE: u64 = 0xE000_ED18;

pub fn shpr_w_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    // SHPR{1,2,3} controls priorities of system interrupts 4-15
    let nvic = proc.event_controller.get_impl::<Nvic>()?;

    // IPR: 8 bits per interrupt
    let base = address - SHPR_BASE;
    let reg_n = (base / 4) as u32;
    let offset = (base % 4) as u32;

    let mut e = nvic.exceptions.write().unwrap();

    let mut i = 0;
    while i < 4 {
        e[(reg_n * 4 + i + 3 + offset) as usize].set_priority(
            data[i as usize],
            nvic.priority_grouping
                .load(std::sync::atomic::Ordering::Acquire),
        );
        i += 1;
    }
    Ok(())
}

pub fn shcsr_w_hook(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let nvic = proc.event_controller.get_impl::<Nvic>()?;
    let val = u32::from_le_bytes(data[0..4].try_into().unwrap());

    let usgfaultena = (val & (1 << 18)) > 0;
    let busfaultena = (val & (1 << 17)) > 0;
    let memfaultena = (val & (1 << 16)) > 0;

    let svcallpending = (val & (1 << 15)) > 0;
    let busfaultpending = (val & (1 << 14)) > 0;
    let memfaultpending = (val & (1 << 13)) > 0;
    let usgfaultpending = (val & (1 << 12)) > 0;

    if usgfaultena {
        nvic.enable_interrupt(USAGEFAULT_IRQN);
    } else {
        nvic.disable_interrupt(proc.mmu, USAGEFAULT_IRQN);
    }
    if busfaultena {
        nvic.enable_interrupt(BUSFAULT_IRQN);
    } else {
        nvic.disable_interrupt(proc.mmu, BUSFAULT_IRQN);
    }
    if memfaultena {
        nvic.enable_interrupt(MEMMANAGE_IRQN);
    } else {
        nvic.disable_interrupt(proc.mmu, MEMMANAGE_IRQN);
    }

    if svcallpending {
        nvic.set_pending(SVCALL_IRQN);
    } else {
        nvic.clear_pending(SVCALL_IRQN);
    }
    if busfaultpending {
        nvic.set_pending(BUSFAULT_IRQN);
    } else {
        nvic.clear_pending(BUSFAULT_IRQN);
    }
    if memfaultpending {
        nvic.set_pending(MEMMANAGE_IRQN);
    } else {
        nvic.clear_pending(MEMMANAGE_IRQN);
    }
    if usgfaultpending {
        nvic.set_pending(USAGEFAULT_IRQN);
    } else {
        nvic.clear_pending(USAGEFAULT_IRQN);
    }
    Ok(())
}

const ISER_BASE: u64 = 0xE000_E100;
const ICER_BASE: u64 = 0xE000_E180;
const ISPR_BASE: u64 = 0xE000_E200;
const ICPR_BASE: u64 = 0xE000_E280;
const IPR_BASE: u64 = 0xE000_E400;

const ISER_END: u64 = 0xE000_E13C;
const ICER_END: u64 = 0xE000_E1BC;
const ISPR_END: u64 = 0xE000_E23C;
const ICPR_END: u64 = 0xE000_E2BC;
const IABR_END: u64 = 0xE000_E33C;

fn u32_from_arm_word(data: &[u8], size: u32) -> u32 {
    debug_assert!(size <= 4, "writes >4 bytes not supported");

    let mut u32_data = [0u8; 4];
    let bytes_to_copy = size as usize;
    u32_data[0..bytes_to_copy].copy_from_slice(&data[0..bytes_to_copy]);
    u32::from_le_bytes(u32_data)
}

pub fn nvic_control_w_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let nvic = proc.event_controller.get_impl::<Nvic>()?;

    let irqns = get_set_bits(data);

    if address <= ISER_END {
        // 32 bits per ISERn, n = [0,15]
        let base = address - ISER_BASE;
        let offset = (base % 4) as u32 * 8;
        let reg_n = (base / 4) as u32 * 32;

        irqns
            .iter()
            .for_each(|x| nvic.enable_interrupt((*x + reg_n + offset).try_into().unwrap()));
    } else if address <= ICER_END {
        let base = address - ICER_BASE;
        let offset = (base % 4) as u32 * 8;
        let reg_n = (base / 4) as u32 * 32;

        irqns.iter().for_each(|x| {
            nvic.disable_interrupt(proc.mmu, (*x + reg_n + offset).try_into().unwrap())
        });
    } else if address <= ISPR_END {
        let base = address - ISPR_BASE;
        let offset = (base % 4) as u32 * 8;
        let reg_n = (base / 4) as u32 * 32;

        irqns
            .iter()
            .for_each(|x| nvic.set_pending((*x + reg_n + offset).try_into().unwrap()));
    } else if address <= ICPR_END {
        let base = address - ICPR_BASE;
        let offset = (base % 4) as u32 * 8;
        let reg_n = (base / 4) as u32 * 32;

        irqns
            .iter()
            .for_each(|x| nvic.clear_pending((*x + reg_n + offset).try_into().unwrap()));
    } else if address <= IABR_END {
        // read only, do nothing on write
    } else {
        // IPR: 8 bits per interrupt
        let base = address - IPR_BASE;
        let reg_n = (base / 4) as u32;
        let offset = (base % 4) as u32;

        {
            let mut e = nvic.exceptions.write().unwrap();
            let mut i = 0;
            while i < size {
                e[(reg_n * 4 + i + 15 + offset) as usize].set_priority(
                    data[i as usize],
                    nvic.priority_grouping
                        .load(std::sync::atomic::Ordering::Acquire),
                );
                i += 1;
            }
        }

        // now resort the heap
        let mut drained_evts = Vec::new();
        let mut heap = nvic.latched_events.try_lock().unwrap();
        for e in heap.drain() {
            drained_evts.push((e.irqn + 15) as usize);
        }
        let exns = nvic.exceptions.read().unwrap();
        for i in drained_evts {
            heap.push(exns[i]);
        }
    }
    Ok(())
}

pub fn stir_w_hook(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    debug!(
        "Write to STIR of size: {}, with data: {:?}, PC=0x{:08x}",
        _size,
        data,
        proc.cpu.pc().unwrap()
    );
    let nvic = proc.event_controller.get_impl::<Nvic>()?;

    let val = u32_from_arm_word(data, _size);
    let val = (val & 0x1FF) + 16;

    nvic.set_pending(val as i32);
    Ok(())
}

const SYSRESETREQ: u32 = 1 << 2;

pub fn aircr_w_hook(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    debug!(
        "Write to AIRCR of size: {}, with data: {:?}, PC=0x{:08x}",
        _size,
        data,
        proc.cpu.pc().unwrap()
    );
    let nvic = proc.event_controller.get_impl::<Nvic>()?;
    let val = u32_from_arm_word(data, _size);

    let prigroup = (val & 0x700) >> 8;

    nvic.priority_grouping
        .store(prigroup as u8, std::sync::atomic::Ordering::Release);

    // setting this bit triggers a local system reset
    if val & SYSRESETREQ > 0 {
        nvic.reset(proc.cpu, proc.mmu);
    }

    debug!("Priority grouping changed to: {prigroup}");
    Ok(())
}
