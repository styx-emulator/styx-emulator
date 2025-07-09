// SPDX-License-Identifier: BSD-2-Clause
use styx_cyclone_v_hps_sys::{
    generic::{FromBytes, RegisterSpec},
    uart0,
};

#[test]
#[cfg_attr(not(feature = "uart0"), ignore)]
fn test_from_bytes() {
    let bytes = vec![0; 15];
    let uart = unsafe { uart0::RegisterBlock::from_bytes(&bytes) };
    assert!(uart.is_none());

    let bytes = vec![0; 256];
    let uart = unsafe { uart0::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let lcr_reg = uart.lcr();

    // eps is bit 4, dls.length7 is 0x2 at offset 0
    lcr_reg.write(|w| w.eps().set_bit().dls().length7());

    let new_bytes = uart.as_bytes_ref();
    assert_eq!(new_bytes[0xC], 2 + 0b10000);
    assert_eq!(new_bytes.len(), bytes.len());
}

#[test]
#[cfg_attr(not(feature = "uart0"), ignore)]
#[cfg_attr(miri, ignore)] // explictly bypassing tagged rules
fn test_sys_write() {
    let bytes = vec![0; 256];
    let uart = unsafe { uart0::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let lsr = uart.lsr();
    unsafe {
        lsr.sys_modify(|_r, w| w.bi().set_bit());
    }
    // should be set
    assert!(unsafe { lsr.sys_read().bi().bit_is_set() });
}

#[test]
#[cfg_attr(not(feature = "uart0"), ignore)]
#[cfg_attr(miri, ignore)] // explictly bypassing tagged rules
fn test_sys_read() {
    let bytes = vec![0; 256];
    let uart = unsafe { uart0::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let fcr = uart.fcr();
    fcr.write(|w| w.fifoe().set_bit());
    let read_value = unsafe { fcr.sys_read().fifoe().bit_is_set() };
    assert!(read_value);
}

#[test]
#[cfg_attr(not(feature = "uart0"), ignore)]
fn test_offset() {
    const LCR_OFFSET: u64 = uart0::Lcr::offset();
    assert_eq!(12, LCR_OFFSET);
    assert_eq!(12, uart0::lcr::LcrSpec::OFFSET);
}

#[test]
#[cfg_attr(not(feature = "uart0"), ignore)]
#[cfg_attr(miri, ignore)] // the two shared registers alias each other
fn test_from_fcr_iir_overlap() {
    let bytes = vec![0; 256];
    let uart = unsafe { uart0::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let fcr_reg = uart.fcr();
    let iir_reg = uart.iir();

    // fcr and iir do NOT have separate storage.
    unsafe { fcr_reg.write(|w| w.bits(0xdeadbeef)) };
    assert_eq!(iir_reg.read().bits(), 0xdeadbeef);
}
