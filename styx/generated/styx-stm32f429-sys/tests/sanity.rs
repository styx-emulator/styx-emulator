// SPDX-License-Identifier: BSD-2-Clause
use styx_stm32f429_sys::{
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
