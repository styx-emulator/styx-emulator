// SPDX-License-Identifier: BSD-2-Clause

use arbitrary_int::*;
use bitbybit::bitfield;

/// System registers represented as bitfields.
///
/// Info in this file is from target/hexagon/reg_fields_def.h.inc in QEMU,
/// in the fork hex-next from github.com/quic/qemu

/// System Status Register
#[bitfield(u32)]
#[derive(Debug)]
pub struct Ssr {
    #[bits(0..=7, rw)]
    cause: u8,
    #[bits(8..=14, rw)]
    asid: u7,
    // Looks like bit 15 is reserved, or missing.
    #[bit(16, rw)]
    um: bool,
    #[bit(17, rw)]
    ex: bool,
    #[bit(18, rw)]
    ie: bool,
    #[bit(19, rw)]
    gm: bool,
    #[bit(20, rw)]
    v0: bool,
    #[bit(21, rw)]
    v1: bool,
    #[bit(22, rw)]
    bvs: bool,
    #[bit(23, rw)]
    ce: bool,
    #[bit(24, rw)]
    pe: bool,
    #[bit(25, rw)]
    bp: bool,
    #[bit(26, rw)]
    xe2: bool,
    #[bits(27..=29, rw)]
    xa: u3,
    #[bit(30, rw)]
    ss: bool,
    #[bit(31, rw)]
    xe: bool,
}

/// System Configuration register
#[bitfield(u32)]
#[derive(Debug)]
pub struct Syscfg {
    #[bit(0, rw)]
    mmuen: bool,
    #[bit(1, rw)]
    icen: bool,
    #[bit(2, rw)]
    dcen: bool,
    #[bit(3, rw)]
    isdbtrusted: bool,
    #[bit(4, rw)]
    gie: bool,
    #[bit(5, rw)]
    isdbready: bool,
    #[bit(6, rw)]
    pcycleen: bool,
    #[bit(7, rw)]
    v2x: bool,
    #[bit(8, rw)]
    ignoredabort: bool,
    #[bit(9, rw)]
    pm: bool,
    #[bit(11, rw)]
    tlblock: bool,
    #[bit(12, rw)]
    k0lock: bool,
    #[bit(13, rw)]
    bq: bool,
    #[bit(14, rw)]
    prio: bool,
    #[bit(15, rw)]
    dmt: bool,
    #[bits(16..=18, rw)]
    l2cfg: u3,
    #[bit(19, rw)]
    itcm: bool,
    #[bit(21, rw)]
    l2nwa: bool,
    #[bit(22, rw)]
    l2nra: bool,
    #[bit(23, rw)]
    l2wb: bool,
    #[bit(24, rw)]
    l2p: bool,
    #[bits(25..=26, rw)]
    slvctl0: u2,
    #[bits(27..=28, rw)]
    slvctl1: u2,
    #[bits(29..=30, rw)]
    l2partsize: u2,
    #[bit(31, rw)]
    l2gca: bool,
}

#[bitfield(u32)]
#[derive(Debug)]
pub struct Usr {
    #[bit(0, rw)]
    ovf: bool,
    #[bit(1, rw)]
    fpinvf: bool,
    #[bit(2, rw)]
    fpdbzf: bool,
    #[bit(3, rw)]
    fpovff: bool,
    #[bit(4, rw)]
    fpunff: bool,
    #[bit(5, rw)]
    fpinpf: bool,
    #[bits(8..=9, rw)]
    lpcfg: u2,
    #[bits(22..=23, rw)]
    fprnd: u2,
    #[bit(25, rw)]
    fpinve: bool,
    #[bit(26, rw)]
    fpdbze: bool,
    #[bit(27, rw)]
    fpovfe: bool,
    #[bit(28, rw)]
    fpunfe: bool,
    #[bit(29, rw)]
    fpinpe: bool,
}

/// Interrupt pending and auto disable register.
///
/// See 11.9.2 "Clear interrupt auto disable" and "Cancel pending interrupts"
/// for more information.
#[bitfield(u32)]
#[derive(Debug)]
pub struct Ipendad {
    #[bits(0..=15, rw)]
    ipend: u16,
    #[bits(16..=31, rw)]
    iad: u16,
}

#[bitfield(u64)]
#[derive(Debug)]
pub struct Pte {
    // Physical page descriptor
    #[bits(0..=23, rw)]
    ppd: u24,
    #[bits(24..=27, rw)]
    c: u4,
    #[bit(28, rw)]
    u: bool,
    #[bit(29, rw)]
    r: bool,
    #[bit(30, rw)]
    w: bool,
    #[bit(31, rw)]
    x: bool,
    #[bits(32..=51, rw)]
    vpn: u20,
    #[bits(52..=58, rw)]
    asid: u7,
    #[bit(59, rw)]
    atr0: bool,
    #[bit(60, rw)]
    atr1: bool,
    #[bit(61, rw)]
    pa35: bool,
    #[bit(62, rw)]
    g: bool,
    #[bit(63, rw)]
    v: bool,
}

#[bitfield(u32)]
#[derive(Debug)]
pub struct Isdbst {
    #[bit(0, rw)]
    ready: bool,
    #[bit(1, rw)]
    mbxoutstatus: bool,
    #[bit(2, rw)]
    mbxinstatus: bool,
    #[bit(3, rw)]
    procmode: bool,
    #[bit(4, rw)]
    cmdstatus: bool,
    #[bit(5, rw)]
    stuffstatus: bool,
    #[bits(8..=15, rw)]
    debugmode: u8,
    #[bits(16..=23, rw)]
    onoff: u8,
    #[bits(24..=31, rw)]
    waitrun: u8,
}

#[bitfield(u32)]
#[derive(Debug)]
pub struct Ccr {
    #[bits(0..=1, rw)]
    l1icp: u2,
    #[bits(3..=4, rw)]
    l1dcp: u2,
    #[bits(6..=7, rw)]
    l2cp: u2,
    #[bit(16, rw)]
    hfi: bool,
    #[bit(17, rw)]
    hfd: bool,
    #[bit(18, rw)]
    hfil2: bool,
    #[bit(19, rw)]
    hfdl2: bool,
    #[bit(20, rw)]
    sfd: bool,
    #[bit(24, rw)]
    gie: bool,
    #[bit(25, rw)]
    gte: bool,
    #[bit(26, rw)]
    gee: bool,
    #[bit(27, rw)]
    gre: bool,
    #[bit(29, rw)]
    vv1: bool,
    #[bit(30, rw)]
    vv2: bool,
    #[bit(31, rw)]
    vv3: bool,
}
