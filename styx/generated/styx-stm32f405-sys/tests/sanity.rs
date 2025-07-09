// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use styx_stm32f405_sys::{
    generic::{FromBytes, RegisterSpec},
    uart4,
};

#[test]
#[cfg_attr(not(feature = "uart4"), ignore)]
fn test_from_bytes() {
    let bytes = vec![0; 15];
    let uart = unsafe { uart4::RegisterBlock::from_bytes(&bytes) };
    assert!(uart.is_none());

    let bytes = vec![0; 24];
    let uart = unsafe { uart4::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let cr1 = uart.cr1();

    cr1.write(|w| w.pce().set_bit().sbk().set_bit());

    let new_bytes = uart.as_bytes_ref();
    assert_eq!(new_bytes[0xC], 0b1);
    assert_eq!(new_bytes[0xD], 0b100);
    assert_eq!(new_bytes.len(), bytes.len());
}

#[test]
#[cfg_attr(not(feature = "uart4"), ignore)]
fn test_sys_write() {
    let bytes = vec![0; 24];
    let uart = unsafe { uart4::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let cr2 = uart.cr2();
    unsafe {
        cr2.sys_modify(|_r, w| w.lbdie().set_bit());
    }
    // should be set
    assert!(unsafe { cr2.sys_read().lbdie().bit_is_set() });
}

#[test]
#[cfg_attr(not(feature = "uart4"), ignore)]
fn test_sys_read() {
    let bytes = vec![0; 24];
    let uart = unsafe { uart4::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let cr3 = uart.cr3();
    cr3.write(|w| w.dmar().set_bit());
    let read_value = unsafe { cr3.sys_read().dmar().bit_is_set() };
    assert!(read_value);
}

#[test]
#[cfg_attr(not(feature = "uart4"), ignore)]
fn test_offset() {
    const LCR_OFFSET: u64 = uart4::Cr1::offset();
    assert_eq!(12, LCR_OFFSET);
    assert_eq!(12, uart4::cr1::Cr1Spec::OFFSET);
}
