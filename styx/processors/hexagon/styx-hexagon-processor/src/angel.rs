// SPDX-License-Identifier: BSD-2-Clause
//! # ARM ANGEL Semihosting interface implementation for Qualcomm Hexagon

use std::process::exit;

use bitbybit::bitenum;
use styx_core::{
    arch::hexagon::HexagonRegister,
    cpu::{CpuBackend, CpuBackendExt},
    errors::UnknownError,
    memory::Mmu,
    prelude::{log::info, Context},
};

// From QUIC QEMU, branch hex-next:
// target/hexagon/hexswi.c
//
// Some other useful ANGEL calls to implement
// 0x15 - get cmdline
// 0x16 - heap?
#[derive(Debug)]
#[bitenum(u32, exhaustive = false)]
#[allow(unused)]
pub enum AngelCall {
    // Close
    Close = 0x2,
    // Write a buffer of characters
    Write = 0x5,
    // Quit the emulator
    Exit = 0x18,
    // Write a character from the register
    WriteCReg = 0x43,
}

// NOTE: might be a good idea to take out the CPU
// and just return the outcome in the Result instead
// of setting register R0.
pub fn handle_angel(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    swi_no: u32,
    arg: u32,
) -> Result<(), UnknownError> {
    match AngelCall::new_with_raw_value(swi_no) {
        Ok(AngelCall::WriteCReg) => {
            print!("{}", arg as u8 as char);
        }
        Ok(AngelCall::Write) => {
            let arg = arg as u64;
            let fileno = mmu.read_u32_le_virt_data(arg, cpu).unwrap();
            let ptr = mmu.read_u32_le_virt_data(arg + 4, cpu).unwrap();
            let bytes = mmu.read_u32_le_virt_data(arg + 8, cpu).unwrap();

            let mut data = vec![0; bytes as usize];
            mmu.virt_read_data(ptr as u64, &mut data, cpu).unwrap();

            info!("SYS_WRITE data is {data:?}");
            let data_str = str::from_utf8_mut(&mut data).unwrap().to_owned();
            info!("SYS_WRITE no:{fileno} data:{data:x?} bytes:{bytes} str:{data_str}");

            cpu.write_register(HexagonRegister::R0, 0u32)
                .with_context(|| "couldn't write r0 for SYS_WRITE")?;
            print!("{data_str}");
        }
        Ok(AngelCall::Close) => {
            // auto success
            cpu.write_register(HexagonRegister::R0, 0u32)
                .with_context(|| "couldn't write r0 for SYS_CLOSE")?;
        }
        // https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst#sys-exit-0x18
        Ok(AngelCall::Exit) => exit(0),
        Err(swi_no_unk) => {
            info!("unimplemented trap: trap0 swi_no is 0x{swi_no_unk:x}, arg 0x{arg:x}");
        }
    }

    Ok(())
}
