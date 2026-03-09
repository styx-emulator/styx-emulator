// SPDX-License-Identifier: BSD-2-Clause
//! # ARM ANGEL Semihosting interface implementation for Qualcomm Hexagon

// From QUIC QEMU, branch hex-next:
// target/hexagon/hexswi.c
#[repr(u8)]
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

pub fn handle_angel(swi_no: u32, arg: u32) {
    if swi_no == AngelCall::WriteCReg as u32 {
        print!("{}", arg as u8 as char)
    }
}
