// SPDX-License-Identifier: BSD-2-Clause
//! # ARM ANGEL Semihosting interface implementation for Qualcomm Hexagon

use std::sync::Arc;

use bitbybit::bitenum;
use styx_core::{
    arch::hexagon::HexagonRegister,
    cpu::{CpuBackend, CpuBackendExt},
    errors::UnknownError,
    memory::Mmu,
    prelude::{
        log::{info, trace},
        Context,
    },
    sync::styx_async::sync::broadcast,
};

// More info on Angel:
//
// From QUIC QEMU, branch hex-next:
// target/hexagon/hexswi.c. See `sim_handle_trap0` for information on the Angel calling convention.
// In QEMU, semihosting/arm-compat-semi.c may also have useful information. The calling convention is
// also briefly documented below in `handle_angel`.
//
// Also see https://developer.arm.com/documentation/dui0205/g/semihosting/about-semihosting,
// especially the "Semihosting SVCs" section for documentation on common Angel calls and how
// they should be implemented.
//
// In the future, we should also implement the following calls, because they have been seen in
// tests or firmware:
//
// 0x16 - heap info

/// Enum with the different Angel calls and the corresponding call number.
#[derive(Debug)]
#[bitenum(u32, exhaustive = false)]
#[allow(unused)]
pub enum AngelCall {
    // Close
    Close = 0x2,
    // Write a character
    WriteC = 0x3,
    // Write a null terminated string
    Write0 = 0x4,
    // Write a buffer of characters
    Write = 0x5,
    // Get command line arguments
    GetCmdline = 0x15,
    // Quit the emulator
    Exit = 0x18,
    // Write a character from the register
    WriteCReg = 0x43,
}

// NOTE: might be a good idea to take out the CPU
// and just return the outcome in the Result instead
// of setting register R0.

/// This function `handle_angel` handles Angel semihosting
/// calls from Hexagon. Generally speaking, a trap0(#0) is invoked
/// with parameters in registers. Before the interrupt handler is run,
/// the emulator uses the information from the parameters to do something.
///
/// The parameters for Angel are passed as follows:
/// R0 = The Angel call number. This indicates what to do (eg. open a file, print a character, read data from stdin, etc.)
///
/// R1 = The parameter. This might just be some data (eg. a character in the case of "print a character"), but
/// for more complex calls may be a pointer (in the emulated memory space) to a
/// structure with more data (eg. for the WRITE Angel call).
///
/// If applicable, a return value will be placed in R0.
/// Oftentimes, there is no return value, so R0 is unchanged.
pub fn handle_angel(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    swi_no: u32,
    arg: u32,
    tx: Arc<broadcast::Sender<u8>>,
) -> Result<(), UnknownError> {
    match AngelCall::new_with_raw_value(swi_no) {
        // Only return one argument for now
        Ok(AngelCall::Write0) => {
            let str_addr = arg as u64;

            // Read until zero
            let mut i = 0;
            loop {
                let chr = mmu.read_u8_le_virt_data(str_addr + i, cpu).unwrap();

                tx.send(chr)?;
                i += 1;

                // zero terminates a C stirng
                if chr == 0 {
                    break;
                }
            }
        }
        // Only return one argument for now
        Ok(AngelCall::GetCmdline) => {
            if let Some(bin_name) = std::env::args().nth(1) {
                let arg = arg as u64;
                let buf = mmu.read_u32_le_virt_data(arg, cpu).unwrap();
                let buf_len = mmu.read_u32_le_virt_data(arg + 4, cpu).unwrap();

                // add one for null terminator, if check fails then fail out
                if bin_name.len() + 1 > buf_len as usize {
                    trace!("Angel get command line failed with buf name {:x} and supplied buf_len {:x}", bin_name.len()+1, buf_len);
                    // in quic QEMU, tests/tcg/hexagon/system/crt0/min_libc.c,
                    // SYS_GET_CMDLINE will fail is the return value is not zero.
                    cpu.write_register(HexagonRegister::R0, u32::MAX)
                        .with_context(|| "couldn't write r0 for SYS_GET_CMDLINE")?;
                }
                // buffer size test passed
                else {
                    for (i, byt) in bin_name.chars().enumerate() {
                        mmu.write_u8_le_virt_data((buf + i as u32) as u64, byt as u8, cpu)
                            .unwrap();
                    }

                    cpu.write_register(HexagonRegister::R0, 0u32)
                        .with_context(|| "couldn't write r0 for SYS_GET_CMDLINE")?;
                }
            }
        }
        Ok(AngelCall::WriteC) => {
            let chr = mmu.read_u8_le_virt_data(arg as u64, cpu).unwrap();
            tx.send(chr)?;
        }
        Ok(AngelCall::WriteCReg) => {
            tx.send(arg as u8)?;
        }
        Ok(AngelCall::Write) => {
            let arg = arg as u64;
            let fileno = mmu.read_u32_le_virt_data(arg, cpu).unwrap();
            let ptr = mmu.read_u32_le_virt_data(arg + 4, cpu).unwrap();
            let bytes = mmu.read_u32_le_virt_data(arg + 8, cpu).unwrap();

            let mut data = vec![0; bytes as usize];
            mmu.virt_read_data(ptr as u64, &mut data, cpu).unwrap();

            info!("SYS_WRITE data is {data:?}");
            for chr in &mut data {
                tx.send(*chr)?;
            }
            let data_str = str::from_utf8_mut(&mut data).unwrap().to_owned();
            info!("SYS_WRITE no:{fileno} data:{data:x?} bytes:{bytes} str:{data_str}");

            cpu.write_register(HexagonRegister::R0, 0u32)
                .with_context(|| "couldn't write r0 for SYS_WRITE")?;
        }
        Ok(AngelCall::Close) => {
            // auto success
            cpu.write_register(HexagonRegister::R0, 0u32)
                .with_context(|| "couldn't write r0 for SYS_CLOSE")?;
        }
        // https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst#sys-exit-0x18
        Ok(AngelCall::Exit) => {
            cpu.stop();
        }
        Err(swi_no_unk) => {
            info!("unimplemented trap: trap0 swi_no is 0x{swi_no_unk:x}, arg 0x{arg:x}");
        }
    }

    Ok(())
}
