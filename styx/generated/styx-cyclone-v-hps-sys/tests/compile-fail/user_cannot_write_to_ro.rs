// SPDX-License-Identifier: BSD-2-Clause
extern crate styx_cyclone_v_hps_sys;

use styx_cyclone_v_hps_sys::{
    generic::{FromBytes, RegisterSpec},
    uart0,
};

// if this builds then users are allowed to write to read only sections
fn main() {
    let bytes = vec![0; 256];
    let uart = unsafe { uart0::RegisterBlock::from_bytes(&bytes) }.unwrap();

    let lsr = uart.lsr();

    let output = lsr.write(|w| w.bi().set_bit()); //~ ERROR the method `write` exists for reference `&Reg<LsrSpec>`, but its trait bounds were not satisfied
}
