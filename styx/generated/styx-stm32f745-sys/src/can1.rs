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
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    mcr: Mcr,
    msr: Msr,
    tsr: Tsr,
    rf0r: Rf0r,
    rf1r: Rf1r,
    ier: Ier,
    esr: Esr,
    btr: Btr,
    _reserved8: [u8; 0x0160],
    ti0r: Ti0r,
    tdt0r: Tdt0r,
    tdl0r: Tdl0r,
    tdh0r: Tdh0r,
    ti1r: Ti1r,
    tdt1r: Tdt1r,
    tdl1r: Tdl1r,
    tdh1r: Tdh1r,
    ti2r: Ti2r,
    tdt2r: Tdt2r,
    tdl2r: Tdl2r,
    tdh2r: Tdh2r,
    ri0r: Ri0r,
    rdt0r: Rdt0r,
    rdl0r: Rdl0r,
    rdh0r: Rdh0r,
    ri1r: Ri1r,
    rdt1r: Rdt1r,
    rdl1r: Rdl1r,
    rdh1r: Rdh1r,
    _reserved28: [u8; 0x30],
    fmr: Fmr,
    fm1r: Fm1r,
    _reserved30: [u8; 0x04],
    fs1r: Fs1r,
    _reserved31: [u8; 0x04],
    ffa1r: Ffa1r,
    _reserved32: [u8; 0x04],
    fa1r: Fa1r,
    _reserved33: [u8; 0x20],
    f0r1: F0r1,
    f0r2: F0r2,
    f1r1: F1r1,
    f1r2: F1r2,
    f2r1: F2r1,
    f2r2: F2r2,
    f3r1: F3r1,
    f3r2: F3r2,
    f4r1: F4r1,
    f4r2: F4r2,
    f5r1: F5r1,
    f5r2: F5r2,
    f6r1: F6r1,
    f6r2: F6r2,
    f7r1: F7r1,
    f7r2: F7r2,
    f8r1: F8r1,
    f8r2: F8r2,
    f9r1: F9r1,
    f9r2: F9r2,
    f10r1: F10r1,
    f10r2: F10r2,
    f11r1: F11r1,
    f11r2: F11r2,
    f12r1: F12r1,
    f12r2: F12r2,
    f13r1: F13r1,
    f13r2: F13r2,
    f14r1: F14r1,
    f14r2: F14r2,
    f15r1: F15r1,
    f15r2: F15r2,
    f16r1: F16r1,
    f16r2: F16r2,
    f17r1: F17r1,
    f17r2: F17r2,
    f18r1: F18r1,
    f18r2: F18r2,
    f19r1: F19r1,
    f19r2: F19r2,
    f20r1: F20r1,
    f20r2: F20r2,
    f21r1: F21r1,
    f21r2: F21r2,
    f22r1: F22r1,
    f22r2: F22r2,
    f23r1: F23r1,
    f23r2: F23r2,
    f24r1: F24r1,
    f24r2: F24r2,
    f25r1: F25r1,
    f25r2: F25r2,
    f26r1: F26r1,
    f26r2: F26r2,
    f27r1: F27r1,
    f27r2: F27r2,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - master control register"]
    #[inline(always)]
    pub const fn mcr(&self) -> &Mcr {
        &self.mcr
    }
    #[doc = "0x04 - master status register"]
    #[inline(always)]
    pub const fn msr(&self) -> &Msr {
        &self.msr
    }
    #[doc = "0x08 - transmit status register"]
    #[inline(always)]
    pub const fn tsr(&self) -> &Tsr {
        &self.tsr
    }
    #[doc = "0x0c - receive FIFO 0 register"]
    #[inline(always)]
    pub const fn rf0r(&self) -> &Rf0r {
        &self.rf0r
    }
    #[doc = "0x10 - receive FIFO 1 register"]
    #[inline(always)]
    pub const fn rf1r(&self) -> &Rf1r {
        &self.rf1r
    }
    #[doc = "0x14 - interrupt enable register"]
    #[inline(always)]
    pub const fn ier(&self) -> &Ier {
        &self.ier
    }
    #[doc = "0x18 - interrupt enable register"]
    #[inline(always)]
    pub const fn esr(&self) -> &Esr {
        &self.esr
    }
    #[doc = "0x1c - bit timing register"]
    #[inline(always)]
    pub const fn btr(&self) -> &Btr {
        &self.btr
    }
    #[doc = "0x180 - TX mailbox identifier register"]
    #[inline(always)]
    pub const fn ti0r(&self) -> &Ti0r {
        &self.ti0r
    }
    #[doc = "0x184 - mailbox data length control and time stamp register"]
    #[inline(always)]
    pub const fn tdt0r(&self) -> &Tdt0r {
        &self.tdt0r
    }
    #[doc = "0x188 - mailbox data low register"]
    #[inline(always)]
    pub const fn tdl0r(&self) -> &Tdl0r {
        &self.tdl0r
    }
    #[doc = "0x18c - mailbox data high register"]
    #[inline(always)]
    pub const fn tdh0r(&self) -> &Tdh0r {
        &self.tdh0r
    }
    #[doc = "0x190 - mailbox identifier register"]
    #[inline(always)]
    pub const fn ti1r(&self) -> &Ti1r {
        &self.ti1r
    }
    #[doc = "0x194 - mailbox data length control and time stamp register"]
    #[inline(always)]
    pub const fn tdt1r(&self) -> &Tdt1r {
        &self.tdt1r
    }
    #[doc = "0x198 - mailbox data low register"]
    #[inline(always)]
    pub const fn tdl1r(&self) -> &Tdl1r {
        &self.tdl1r
    }
    #[doc = "0x19c - mailbox data high register"]
    #[inline(always)]
    pub const fn tdh1r(&self) -> &Tdh1r {
        &self.tdh1r
    }
    #[doc = "0x1a0 - mailbox identifier register"]
    #[inline(always)]
    pub const fn ti2r(&self) -> &Ti2r {
        &self.ti2r
    }
    #[doc = "0x1a4 - mailbox data length control and time stamp register"]
    #[inline(always)]
    pub const fn tdt2r(&self) -> &Tdt2r {
        &self.tdt2r
    }
    #[doc = "0x1a8 - mailbox data low register"]
    #[inline(always)]
    pub const fn tdl2r(&self) -> &Tdl2r {
        &self.tdl2r
    }
    #[doc = "0x1ac - mailbox data high register"]
    #[inline(always)]
    pub const fn tdh2r(&self) -> &Tdh2r {
        &self.tdh2r
    }
    #[doc = "0x1b0 - receive FIFO mailbox identifier register"]
    #[inline(always)]
    pub const fn ri0r(&self) -> &Ri0r {
        &self.ri0r
    }
    #[doc = "0x1b4 - mailbox data high register"]
    #[inline(always)]
    pub const fn rdt0r(&self) -> &Rdt0r {
        &self.rdt0r
    }
    #[doc = "0x1b8 - mailbox data high register"]
    #[inline(always)]
    pub const fn rdl0r(&self) -> &Rdl0r {
        &self.rdl0r
    }
    #[doc = "0x1bc - receive FIFO mailbox data high register"]
    #[inline(always)]
    pub const fn rdh0r(&self) -> &Rdh0r {
        &self.rdh0r
    }
    #[doc = "0x1c0 - mailbox data high register"]
    #[inline(always)]
    pub const fn ri1r(&self) -> &Ri1r {
        &self.ri1r
    }
    #[doc = "0x1c4 - mailbox data high register"]
    #[inline(always)]
    pub const fn rdt1r(&self) -> &Rdt1r {
        &self.rdt1r
    }
    #[doc = "0x1c8 - mailbox data high register"]
    #[inline(always)]
    pub const fn rdl1r(&self) -> &Rdl1r {
        &self.rdl1r
    }
    #[doc = "0x1cc - mailbox data high register"]
    #[inline(always)]
    pub const fn rdh1r(&self) -> &Rdh1r {
        &self.rdh1r
    }
    #[doc = "0x200 - filter master register"]
    #[inline(always)]
    pub const fn fmr(&self) -> &Fmr {
        &self.fmr
    }
    #[doc = "0x204 - filter mode register"]
    #[inline(always)]
    pub const fn fm1r(&self) -> &Fm1r {
        &self.fm1r
    }
    #[doc = "0x20c - filter scale register"]
    #[inline(always)]
    pub const fn fs1r(&self) -> &Fs1r {
        &self.fs1r
    }
    #[doc = "0x214 - filter FIFO assignment register"]
    #[inline(always)]
    pub const fn ffa1r(&self) -> &Ffa1r {
        &self.ffa1r
    }
    #[doc = "0x21c - filter activation register"]
    #[inline(always)]
    pub const fn fa1r(&self) -> &Fa1r {
        &self.fa1r
    }
    #[doc = "0x240 - Filter bank 0 register 1"]
    #[inline(always)]
    pub const fn f0r1(&self) -> &F0r1 {
        &self.f0r1
    }
    #[doc = "0x244 - Filter bank 0 register 2"]
    #[inline(always)]
    pub const fn f0r2(&self) -> &F0r2 {
        &self.f0r2
    }
    #[doc = "0x248 - Filter bank 1 register 1"]
    #[inline(always)]
    pub const fn f1r1(&self) -> &F1r1 {
        &self.f1r1
    }
    #[doc = "0x24c - Filter bank 1 register 2"]
    #[inline(always)]
    pub const fn f1r2(&self) -> &F1r2 {
        &self.f1r2
    }
    #[doc = "0x250 - Filter bank 2 register 1"]
    #[inline(always)]
    pub const fn f2r1(&self) -> &F2r1 {
        &self.f2r1
    }
    #[doc = "0x254 - Filter bank 2 register 2"]
    #[inline(always)]
    pub const fn f2r2(&self) -> &F2r2 {
        &self.f2r2
    }
    #[doc = "0x258 - Filter bank 3 register 1"]
    #[inline(always)]
    pub const fn f3r1(&self) -> &F3r1 {
        &self.f3r1
    }
    #[doc = "0x25c - Filter bank 3 register 2"]
    #[inline(always)]
    pub const fn f3r2(&self) -> &F3r2 {
        &self.f3r2
    }
    #[doc = "0x260 - Filter bank 4 register 1"]
    #[inline(always)]
    pub const fn f4r1(&self) -> &F4r1 {
        &self.f4r1
    }
    #[doc = "0x264 - Filter bank 4 register 2"]
    #[inline(always)]
    pub const fn f4r2(&self) -> &F4r2 {
        &self.f4r2
    }
    #[doc = "0x268 - Filter bank 5 register 1"]
    #[inline(always)]
    pub const fn f5r1(&self) -> &F5r1 {
        &self.f5r1
    }
    #[doc = "0x26c - Filter bank 5 register 2"]
    #[inline(always)]
    pub const fn f5r2(&self) -> &F5r2 {
        &self.f5r2
    }
    #[doc = "0x270 - Filter bank 6 register 1"]
    #[inline(always)]
    pub const fn f6r1(&self) -> &F6r1 {
        &self.f6r1
    }
    #[doc = "0x274 - Filter bank 6 register 2"]
    #[inline(always)]
    pub const fn f6r2(&self) -> &F6r2 {
        &self.f6r2
    }
    #[doc = "0x278 - Filter bank 7 register 1"]
    #[inline(always)]
    pub const fn f7r1(&self) -> &F7r1 {
        &self.f7r1
    }
    #[doc = "0x27c - Filter bank 7 register 2"]
    #[inline(always)]
    pub const fn f7r2(&self) -> &F7r2 {
        &self.f7r2
    }
    #[doc = "0x280 - Filter bank 8 register 1"]
    #[inline(always)]
    pub const fn f8r1(&self) -> &F8r1 {
        &self.f8r1
    }
    #[doc = "0x284 - Filter bank 8 register 2"]
    #[inline(always)]
    pub const fn f8r2(&self) -> &F8r2 {
        &self.f8r2
    }
    #[doc = "0x288 - Filter bank 9 register 1"]
    #[inline(always)]
    pub const fn f9r1(&self) -> &F9r1 {
        &self.f9r1
    }
    #[doc = "0x28c - Filter bank 9 register 2"]
    #[inline(always)]
    pub const fn f9r2(&self) -> &F9r2 {
        &self.f9r2
    }
    #[doc = "0x290 - Filter bank 10 register 1"]
    #[inline(always)]
    pub const fn f10r1(&self) -> &F10r1 {
        &self.f10r1
    }
    #[doc = "0x294 - Filter bank 10 register 2"]
    #[inline(always)]
    pub const fn f10r2(&self) -> &F10r2 {
        &self.f10r2
    }
    #[doc = "0x298 - Filter bank 11 register 1"]
    #[inline(always)]
    pub const fn f11r1(&self) -> &F11r1 {
        &self.f11r1
    }
    #[doc = "0x29c - Filter bank 11 register 2"]
    #[inline(always)]
    pub const fn f11r2(&self) -> &F11r2 {
        &self.f11r2
    }
    #[doc = "0x2a0 - Filter bank 4 register 1"]
    #[inline(always)]
    pub const fn f12r1(&self) -> &F12r1 {
        &self.f12r1
    }
    #[doc = "0x2a4 - Filter bank 12 register 2"]
    #[inline(always)]
    pub const fn f12r2(&self) -> &F12r2 {
        &self.f12r2
    }
    #[doc = "0x2a8 - Filter bank 13 register 1"]
    #[inline(always)]
    pub const fn f13r1(&self) -> &F13r1 {
        &self.f13r1
    }
    #[doc = "0x2ac - Filter bank 13 register 2"]
    #[inline(always)]
    pub const fn f13r2(&self) -> &F13r2 {
        &self.f13r2
    }
    #[doc = "0x2b0 - Filter bank 14 register 1"]
    #[inline(always)]
    pub const fn f14r1(&self) -> &F14r1 {
        &self.f14r1
    }
    #[doc = "0x2b4 - Filter bank 14 register 2"]
    #[inline(always)]
    pub const fn f14r2(&self) -> &F14r2 {
        &self.f14r2
    }
    #[doc = "0x2b8 - Filter bank 15 register 1"]
    #[inline(always)]
    pub const fn f15r1(&self) -> &F15r1 {
        &self.f15r1
    }
    #[doc = "0x2bc - Filter bank 15 register 2"]
    #[inline(always)]
    pub const fn f15r2(&self) -> &F15r2 {
        &self.f15r2
    }
    #[doc = "0x2c0 - Filter bank 16 register 1"]
    #[inline(always)]
    pub const fn f16r1(&self) -> &F16r1 {
        &self.f16r1
    }
    #[doc = "0x2c4 - Filter bank 16 register 2"]
    #[inline(always)]
    pub const fn f16r2(&self) -> &F16r2 {
        &self.f16r2
    }
    #[doc = "0x2c8 - Filter bank 17 register 1"]
    #[inline(always)]
    pub const fn f17r1(&self) -> &F17r1 {
        &self.f17r1
    }
    #[doc = "0x2cc - Filter bank 17 register 2"]
    #[inline(always)]
    pub const fn f17r2(&self) -> &F17r2 {
        &self.f17r2
    }
    #[doc = "0x2d0 - Filter bank 18 register 1"]
    #[inline(always)]
    pub const fn f18r1(&self) -> &F18r1 {
        &self.f18r1
    }
    #[doc = "0x2d4 - Filter bank 18 register 2"]
    #[inline(always)]
    pub const fn f18r2(&self) -> &F18r2 {
        &self.f18r2
    }
    #[doc = "0x2d8 - Filter bank 19 register 1"]
    #[inline(always)]
    pub const fn f19r1(&self) -> &F19r1 {
        &self.f19r1
    }
    #[doc = "0x2dc - Filter bank 19 register 2"]
    #[inline(always)]
    pub const fn f19r2(&self) -> &F19r2 {
        &self.f19r2
    }
    #[doc = "0x2e0 - Filter bank 20 register 1"]
    #[inline(always)]
    pub const fn f20r1(&self) -> &F20r1 {
        &self.f20r1
    }
    #[doc = "0x2e4 - Filter bank 20 register 2"]
    #[inline(always)]
    pub const fn f20r2(&self) -> &F20r2 {
        &self.f20r2
    }
    #[doc = "0x2e8 - Filter bank 21 register 1"]
    #[inline(always)]
    pub const fn f21r1(&self) -> &F21r1 {
        &self.f21r1
    }
    #[doc = "0x2ec - Filter bank 21 register 2"]
    #[inline(always)]
    pub const fn f21r2(&self) -> &F21r2 {
        &self.f21r2
    }
    #[doc = "0x2f0 - Filter bank 22 register 1"]
    #[inline(always)]
    pub const fn f22r1(&self) -> &F22r1 {
        &self.f22r1
    }
    #[doc = "0x2f4 - Filter bank 22 register 2"]
    #[inline(always)]
    pub const fn f22r2(&self) -> &F22r2 {
        &self.f22r2
    }
    #[doc = "0x2f8 - Filter bank 23 register 1"]
    #[inline(always)]
    pub const fn f23r1(&self) -> &F23r1 {
        &self.f23r1
    }
    #[doc = "0x2fc - Filter bank 23 register 2"]
    #[inline(always)]
    pub const fn f23r2(&self) -> &F23r2 {
        &self.f23r2
    }
    #[doc = "0x300 - Filter bank 24 register 1"]
    #[inline(always)]
    pub const fn f24r1(&self) -> &F24r1 {
        &self.f24r1
    }
    #[doc = "0x304 - Filter bank 24 register 2"]
    #[inline(always)]
    pub const fn f24r2(&self) -> &F24r2 {
        &self.f24r2
    }
    #[doc = "0x308 - Filter bank 25 register 1"]
    #[inline(always)]
    pub const fn f25r1(&self) -> &F25r1 {
        &self.f25r1
    }
    #[doc = "0x30c - Filter bank 25 register 2"]
    #[inline(always)]
    pub const fn f25r2(&self) -> &F25r2 {
        &self.f25r2
    }
    #[doc = "0x310 - Filter bank 26 register 1"]
    #[inline(always)]
    pub const fn f26r1(&self) -> &F26r1 {
        &self.f26r1
    }
    #[doc = "0x314 - Filter bank 26 register 2"]
    #[inline(always)]
    pub const fn f26r2(&self) -> &F26r2 {
        &self.f26r2
    }
    #[doc = "0x318 - Filter bank 27 register 1"]
    #[inline(always)]
    pub const fn f27r1(&self) -> &F27r1 {
        &self.f27r1
    }
    #[doc = "0x31c - Filter bank 27 register 2"]
    #[inline(always)]
    pub const fn f27r2(&self) -> &F27r2 {
        &self.f27r2
    }
}
#[doc = "MCR (rw) register accessor: master control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mcr`]
module"]
#[doc(alias = "MCR")]
pub type Mcr = crate::Reg<mcr::McrSpec>;
#[doc = "master control register"]
pub mod mcr;
#[doc = "MSR (rw) register accessor: master status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msr`]
module"]
#[doc(alias = "MSR")]
pub type Msr = crate::Reg<msr::MsrSpec>;
#[doc = "master status register"]
pub mod msr;
#[doc = "TSR (rw) register accessor: transmit status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tsr`]
module"]
#[doc(alias = "TSR")]
pub type Tsr = crate::Reg<tsr::TsrSpec>;
#[doc = "transmit status register"]
pub mod tsr;
#[doc = "RF0R (rw) register accessor: receive FIFO 0 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rf0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rf0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rf0r`]
module"]
#[doc(alias = "RF0R")]
pub type Rf0r = crate::Reg<rf0r::Rf0rSpec>;
#[doc = "receive FIFO 0 register"]
pub mod rf0r;
#[doc = "RF1R (rw) register accessor: receive FIFO 1 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rf1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rf1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rf1r`]
module"]
#[doc(alias = "RF1R")]
pub type Rf1r = crate::Reg<rf1r::Rf1rSpec>;
#[doc = "receive FIFO 1 register"]
pub mod rf1r;
#[doc = "IER (rw) register accessor: interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ier::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ier::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ier`]
module"]
#[doc(alias = "IER")]
pub type Ier = crate::Reg<ier::IerSpec>;
#[doc = "interrupt enable register"]
pub mod ier;
#[doc = "ESR (rw) register accessor: interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`esr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`esr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@esr`]
module"]
#[doc(alias = "ESR")]
pub type Esr = crate::Reg<esr::EsrSpec>;
#[doc = "interrupt enable register"]
pub mod esr;
#[doc = "BTR (rw) register accessor: bit timing register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`btr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`btr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@btr`]
module"]
#[doc(alias = "BTR")]
pub type Btr = crate::Reg<btr::BtrSpec>;
#[doc = "bit timing register"]
pub mod btr;
#[doc = "TI0R (rw) register accessor: TX mailbox identifier register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ti0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ti0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ti0r`]
module"]
#[doc(alias = "TI0R")]
pub type Ti0r = crate::Reg<ti0r::Ti0rSpec>;
#[doc = "TX mailbox identifier register"]
pub mod ti0r;
#[doc = "TDT0R (rw) register accessor: mailbox data length control and time stamp register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdt0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdt0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdt0r`]
module"]
#[doc(alias = "TDT0R")]
pub type Tdt0r = crate::Reg<tdt0r::Tdt0rSpec>;
#[doc = "mailbox data length control and time stamp register"]
pub mod tdt0r;
#[doc = "TDL0R (rw) register accessor: mailbox data low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdl0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdl0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdl0r`]
module"]
#[doc(alias = "TDL0R")]
pub type Tdl0r = crate::Reg<tdl0r::Tdl0rSpec>;
#[doc = "mailbox data low register"]
pub mod tdl0r;
#[doc = "TDH0R (rw) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdh0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdh0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdh0r`]
module"]
#[doc(alias = "TDH0R")]
pub type Tdh0r = crate::Reg<tdh0r::Tdh0rSpec>;
#[doc = "mailbox data high register"]
pub mod tdh0r;
#[doc = "TI1R (rw) register accessor: mailbox identifier register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ti1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ti1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ti1r`]
module"]
#[doc(alias = "TI1R")]
pub type Ti1r = crate::Reg<ti1r::Ti1rSpec>;
#[doc = "mailbox identifier register"]
pub mod ti1r;
#[doc = "TDT1R (rw) register accessor: mailbox data length control and time stamp register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdt1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdt1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdt1r`]
module"]
#[doc(alias = "TDT1R")]
pub type Tdt1r = crate::Reg<tdt1r::Tdt1rSpec>;
#[doc = "mailbox data length control and time stamp register"]
pub mod tdt1r;
#[doc = "TDL1R (rw) register accessor: mailbox data low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdl1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdl1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdl1r`]
module"]
#[doc(alias = "TDL1R")]
pub type Tdl1r = crate::Reg<tdl1r::Tdl1rSpec>;
#[doc = "mailbox data low register"]
pub mod tdl1r;
#[doc = "TDH1R (rw) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdh1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdh1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdh1r`]
module"]
#[doc(alias = "TDH1R")]
pub type Tdh1r = crate::Reg<tdh1r::Tdh1rSpec>;
#[doc = "mailbox data high register"]
pub mod tdh1r;
#[doc = "TI2R (rw) register accessor: mailbox identifier register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ti2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ti2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ti2r`]
module"]
#[doc(alias = "TI2R")]
pub type Ti2r = crate::Reg<ti2r::Ti2rSpec>;
#[doc = "mailbox identifier register"]
pub mod ti2r;
#[doc = "TDT2R (rw) register accessor: mailbox data length control and time stamp register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdt2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdt2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdt2r`]
module"]
#[doc(alias = "TDT2R")]
pub type Tdt2r = crate::Reg<tdt2r::Tdt2rSpec>;
#[doc = "mailbox data length control and time stamp register"]
pub mod tdt2r;
#[doc = "TDL2R (rw) register accessor: mailbox data low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdl2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdl2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdl2r`]
module"]
#[doc(alias = "TDL2R")]
pub type Tdl2r = crate::Reg<tdl2r::Tdl2rSpec>;
#[doc = "mailbox data low register"]
pub mod tdl2r;
#[doc = "TDH2R (rw) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tdh2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tdh2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tdh2r`]
module"]
#[doc(alias = "TDH2R")]
pub type Tdh2r = crate::Reg<tdh2r::Tdh2rSpec>;
#[doc = "mailbox data high register"]
pub mod tdh2r;
#[doc = "RI0R (r) register accessor: receive FIFO mailbox identifier register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ri0r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ri0r`]
module"]
#[doc(alias = "RI0R")]
pub type Ri0r = crate::Reg<ri0r::Ri0rSpec>;
#[doc = "receive FIFO mailbox identifier register"]
pub mod ri0r;
#[doc = "RDT0R (r) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdt0r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rdt0r`]
module"]
#[doc(alias = "RDT0R")]
pub type Rdt0r = crate::Reg<rdt0r::Rdt0rSpec>;
#[doc = "mailbox data high register"]
pub mod rdt0r;
#[doc = "RDL0R (r) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdl0r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rdl0r`]
module"]
#[doc(alias = "RDL0R")]
pub type Rdl0r = crate::Reg<rdl0r::Rdl0rSpec>;
#[doc = "mailbox data high register"]
pub mod rdl0r;
#[doc = "RDH0R (r) register accessor: receive FIFO mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdh0r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rdh0r`]
module"]
#[doc(alias = "RDH0R")]
pub type Rdh0r = crate::Reg<rdh0r::Rdh0rSpec>;
#[doc = "receive FIFO mailbox data high register"]
pub mod rdh0r;
#[doc = "RI1R (r) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ri1r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ri1r`]
module"]
#[doc(alias = "RI1R")]
pub type Ri1r = crate::Reg<ri1r::Ri1rSpec>;
#[doc = "mailbox data high register"]
pub mod ri1r;
#[doc = "RDT1R (r) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdt1r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rdt1r`]
module"]
#[doc(alias = "RDT1R")]
pub type Rdt1r = crate::Reg<rdt1r::Rdt1rSpec>;
#[doc = "mailbox data high register"]
pub mod rdt1r;
#[doc = "RDL1R (r) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdl1r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rdl1r`]
module"]
#[doc(alias = "RDL1R")]
pub type Rdl1r = crate::Reg<rdl1r::Rdl1rSpec>;
#[doc = "mailbox data high register"]
pub mod rdl1r;
#[doc = "RDH1R (r) register accessor: mailbox data high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rdh1r::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rdh1r`]
module"]
#[doc(alias = "RDH1R")]
pub type Rdh1r = crate::Reg<rdh1r::Rdh1rSpec>;
#[doc = "mailbox data high register"]
pub mod rdh1r;
#[doc = "FMR (rw) register accessor: filter master register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fmr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fmr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fmr`]
module"]
#[doc(alias = "FMR")]
pub type Fmr = crate::Reg<fmr::FmrSpec>;
#[doc = "filter master register"]
pub mod fmr;
#[doc = "FM1R (rw) register accessor: filter mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fm1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fm1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fm1r`]
module"]
#[doc(alias = "FM1R")]
pub type Fm1r = crate::Reg<fm1r::Fm1rSpec>;
#[doc = "filter mode register"]
pub mod fm1r;
#[doc = "FS1R (rw) register accessor: filter scale register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs1r`]
module"]
#[doc(alias = "FS1R")]
pub type Fs1r = crate::Reg<fs1r::Fs1rSpec>;
#[doc = "filter scale register"]
pub mod fs1r;
#[doc = "FFA1R (rw) register accessor: filter FIFO assignment register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ffa1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ffa1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ffa1r`]
module"]
#[doc(alias = "FFA1R")]
pub type Ffa1r = crate::Reg<ffa1r::Ffa1rSpec>;
#[doc = "filter FIFO assignment register"]
pub mod ffa1r;
#[doc = "FA1R (rw) register accessor: filter activation register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fa1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fa1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fa1r`]
module"]
#[doc(alias = "FA1R")]
pub type Fa1r = crate::Reg<fa1r::Fa1rSpec>;
#[doc = "filter activation register"]
pub mod fa1r;
#[doc = "F0R1 (rw) register accessor: Filter bank 0 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f0r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f0r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f0r1`]
module"]
#[doc(alias = "F0R1")]
pub type F0r1 = crate::Reg<f0r1::F0r1Spec>;
#[doc = "Filter bank 0 register 1"]
pub mod f0r1;
#[doc = "F0R2 (rw) register accessor: Filter bank 0 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f0r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f0r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f0r2`]
module"]
#[doc(alias = "F0R2")]
pub type F0r2 = crate::Reg<f0r2::F0r2Spec>;
#[doc = "Filter bank 0 register 2"]
pub mod f0r2;
#[doc = "F1R1 (rw) register accessor: Filter bank 1 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f1r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f1r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f1r1`]
module"]
#[doc(alias = "F1R1")]
pub type F1r1 = crate::Reg<f1r1::F1r1Spec>;
#[doc = "Filter bank 1 register 1"]
pub mod f1r1;
#[doc = "F1R2 (rw) register accessor: Filter bank 1 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f1r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f1r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f1r2`]
module"]
#[doc(alias = "F1R2")]
pub type F1r2 = crate::Reg<f1r2::F1r2Spec>;
#[doc = "Filter bank 1 register 2"]
pub mod f1r2;
#[doc = "F2R1 (rw) register accessor: Filter bank 2 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f2r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f2r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f2r1`]
module"]
#[doc(alias = "F2R1")]
pub type F2r1 = crate::Reg<f2r1::F2r1Spec>;
#[doc = "Filter bank 2 register 1"]
pub mod f2r1;
#[doc = "F2R2 (rw) register accessor: Filter bank 2 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f2r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f2r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f2r2`]
module"]
#[doc(alias = "F2R2")]
pub type F2r2 = crate::Reg<f2r2::F2r2Spec>;
#[doc = "Filter bank 2 register 2"]
pub mod f2r2;
#[doc = "F3R1 (rw) register accessor: Filter bank 3 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f3r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f3r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f3r1`]
module"]
#[doc(alias = "F3R1")]
pub type F3r1 = crate::Reg<f3r1::F3r1Spec>;
#[doc = "Filter bank 3 register 1"]
pub mod f3r1;
#[doc = "F3R2 (rw) register accessor: Filter bank 3 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f3r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f3r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f3r2`]
module"]
#[doc(alias = "F3R2")]
pub type F3r2 = crate::Reg<f3r2::F3r2Spec>;
#[doc = "Filter bank 3 register 2"]
pub mod f3r2;
#[doc = "F4R1 (rw) register accessor: Filter bank 4 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f4r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f4r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f4r1`]
module"]
#[doc(alias = "F4R1")]
pub type F4r1 = crate::Reg<f4r1::F4r1Spec>;
#[doc = "Filter bank 4 register 1"]
pub mod f4r1;
#[doc = "F4R2 (rw) register accessor: Filter bank 4 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f4r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f4r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f4r2`]
module"]
#[doc(alias = "F4R2")]
pub type F4r2 = crate::Reg<f4r2::F4r2Spec>;
#[doc = "Filter bank 4 register 2"]
pub mod f4r2;
#[doc = "F5R1 (rw) register accessor: Filter bank 5 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f5r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f5r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f5r1`]
module"]
#[doc(alias = "F5R1")]
pub type F5r1 = crate::Reg<f5r1::F5r1Spec>;
#[doc = "Filter bank 5 register 1"]
pub mod f5r1;
#[doc = "F5R2 (rw) register accessor: Filter bank 5 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f5r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f5r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f5r2`]
module"]
#[doc(alias = "F5R2")]
pub type F5r2 = crate::Reg<f5r2::F5r2Spec>;
#[doc = "Filter bank 5 register 2"]
pub mod f5r2;
#[doc = "F6R1 (rw) register accessor: Filter bank 6 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f6r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f6r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f6r1`]
module"]
#[doc(alias = "F6R1")]
pub type F6r1 = crate::Reg<f6r1::F6r1Spec>;
#[doc = "Filter bank 6 register 1"]
pub mod f6r1;
#[doc = "F6R2 (rw) register accessor: Filter bank 6 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f6r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f6r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f6r2`]
module"]
#[doc(alias = "F6R2")]
pub type F6r2 = crate::Reg<f6r2::F6r2Spec>;
#[doc = "Filter bank 6 register 2"]
pub mod f6r2;
#[doc = "F7R1 (rw) register accessor: Filter bank 7 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f7r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f7r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f7r1`]
module"]
#[doc(alias = "F7R1")]
pub type F7r1 = crate::Reg<f7r1::F7r1Spec>;
#[doc = "Filter bank 7 register 1"]
pub mod f7r1;
#[doc = "F7R2 (rw) register accessor: Filter bank 7 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f7r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f7r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f7r2`]
module"]
#[doc(alias = "F7R2")]
pub type F7r2 = crate::Reg<f7r2::F7r2Spec>;
#[doc = "Filter bank 7 register 2"]
pub mod f7r2;
#[doc = "F8R1 (rw) register accessor: Filter bank 8 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f8r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f8r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f8r1`]
module"]
#[doc(alias = "F8R1")]
pub type F8r1 = crate::Reg<f8r1::F8r1Spec>;
#[doc = "Filter bank 8 register 1"]
pub mod f8r1;
#[doc = "F8R2 (rw) register accessor: Filter bank 8 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f8r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f8r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f8r2`]
module"]
#[doc(alias = "F8R2")]
pub type F8r2 = crate::Reg<f8r2::F8r2Spec>;
#[doc = "Filter bank 8 register 2"]
pub mod f8r2;
#[doc = "F9R1 (rw) register accessor: Filter bank 9 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f9r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f9r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f9r1`]
module"]
#[doc(alias = "F9R1")]
pub type F9r1 = crate::Reg<f9r1::F9r1Spec>;
#[doc = "Filter bank 9 register 1"]
pub mod f9r1;
#[doc = "F9R2 (rw) register accessor: Filter bank 9 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f9r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f9r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f9r2`]
module"]
#[doc(alias = "F9R2")]
pub type F9r2 = crate::Reg<f9r2::F9r2Spec>;
#[doc = "Filter bank 9 register 2"]
pub mod f9r2;
#[doc = "F10R1 (rw) register accessor: Filter bank 10 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f10r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f10r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f10r1`]
module"]
#[doc(alias = "F10R1")]
pub type F10r1 = crate::Reg<f10r1::F10r1Spec>;
#[doc = "Filter bank 10 register 1"]
pub mod f10r1;
#[doc = "F10R2 (rw) register accessor: Filter bank 10 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f10r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f10r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f10r2`]
module"]
#[doc(alias = "F10R2")]
pub type F10r2 = crate::Reg<f10r2::F10r2Spec>;
#[doc = "Filter bank 10 register 2"]
pub mod f10r2;
#[doc = "F11R1 (rw) register accessor: Filter bank 11 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f11r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f11r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f11r1`]
module"]
#[doc(alias = "F11R1")]
pub type F11r1 = crate::Reg<f11r1::F11r1Spec>;
#[doc = "Filter bank 11 register 1"]
pub mod f11r1;
#[doc = "F11R2 (rw) register accessor: Filter bank 11 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f11r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f11r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f11r2`]
module"]
#[doc(alias = "F11R2")]
pub type F11r2 = crate::Reg<f11r2::F11r2Spec>;
#[doc = "Filter bank 11 register 2"]
pub mod f11r2;
#[doc = "F12R1 (rw) register accessor: Filter bank 4 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f12r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f12r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f12r1`]
module"]
#[doc(alias = "F12R1")]
pub type F12r1 = crate::Reg<f12r1::F12r1Spec>;
#[doc = "Filter bank 4 register 1"]
pub mod f12r1;
#[doc = "F12R2 (rw) register accessor: Filter bank 12 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f12r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f12r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f12r2`]
module"]
#[doc(alias = "F12R2")]
pub type F12r2 = crate::Reg<f12r2::F12r2Spec>;
#[doc = "Filter bank 12 register 2"]
pub mod f12r2;
#[doc = "F13R1 (rw) register accessor: Filter bank 13 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f13r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f13r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f13r1`]
module"]
#[doc(alias = "F13R1")]
pub type F13r1 = crate::Reg<f13r1::F13r1Spec>;
#[doc = "Filter bank 13 register 1"]
pub mod f13r1;
#[doc = "F13R2 (rw) register accessor: Filter bank 13 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f13r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f13r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f13r2`]
module"]
#[doc(alias = "F13R2")]
pub type F13r2 = crate::Reg<f13r2::F13r2Spec>;
#[doc = "Filter bank 13 register 2"]
pub mod f13r2;
#[doc = "F14R1 (rw) register accessor: Filter bank 14 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f14r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f14r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f14r1`]
module"]
#[doc(alias = "F14R1")]
pub type F14r1 = crate::Reg<f14r1::F14r1Spec>;
#[doc = "Filter bank 14 register 1"]
pub mod f14r1;
#[doc = "F14R2 (rw) register accessor: Filter bank 14 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f14r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f14r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f14r2`]
module"]
#[doc(alias = "F14R2")]
pub type F14r2 = crate::Reg<f14r2::F14r2Spec>;
#[doc = "Filter bank 14 register 2"]
pub mod f14r2;
#[doc = "F15R1 (rw) register accessor: Filter bank 15 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f15r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f15r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f15r1`]
module"]
#[doc(alias = "F15R1")]
pub type F15r1 = crate::Reg<f15r1::F15r1Spec>;
#[doc = "Filter bank 15 register 1"]
pub mod f15r1;
#[doc = "F15R2 (rw) register accessor: Filter bank 15 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f15r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f15r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f15r2`]
module"]
#[doc(alias = "F15R2")]
pub type F15r2 = crate::Reg<f15r2::F15r2Spec>;
#[doc = "Filter bank 15 register 2"]
pub mod f15r2;
#[doc = "F16R1 (rw) register accessor: Filter bank 16 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f16r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f16r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f16r1`]
module"]
#[doc(alias = "F16R1")]
pub type F16r1 = crate::Reg<f16r1::F16r1Spec>;
#[doc = "Filter bank 16 register 1"]
pub mod f16r1;
#[doc = "F16R2 (rw) register accessor: Filter bank 16 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f16r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f16r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f16r2`]
module"]
#[doc(alias = "F16R2")]
pub type F16r2 = crate::Reg<f16r2::F16r2Spec>;
#[doc = "Filter bank 16 register 2"]
pub mod f16r2;
#[doc = "F17R1 (rw) register accessor: Filter bank 17 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f17r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f17r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f17r1`]
module"]
#[doc(alias = "F17R1")]
pub type F17r1 = crate::Reg<f17r1::F17r1Spec>;
#[doc = "Filter bank 17 register 1"]
pub mod f17r1;
#[doc = "F17R2 (rw) register accessor: Filter bank 17 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f17r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f17r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f17r2`]
module"]
#[doc(alias = "F17R2")]
pub type F17r2 = crate::Reg<f17r2::F17r2Spec>;
#[doc = "Filter bank 17 register 2"]
pub mod f17r2;
#[doc = "F18R1 (rw) register accessor: Filter bank 18 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f18r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f18r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f18r1`]
module"]
#[doc(alias = "F18R1")]
pub type F18r1 = crate::Reg<f18r1::F18r1Spec>;
#[doc = "Filter bank 18 register 1"]
pub mod f18r1;
#[doc = "F18R2 (rw) register accessor: Filter bank 18 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f18r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f18r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f18r2`]
module"]
#[doc(alias = "F18R2")]
pub type F18r2 = crate::Reg<f18r2::F18r2Spec>;
#[doc = "Filter bank 18 register 2"]
pub mod f18r2;
#[doc = "F19R1 (rw) register accessor: Filter bank 19 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f19r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f19r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f19r1`]
module"]
#[doc(alias = "F19R1")]
pub type F19r1 = crate::Reg<f19r1::F19r1Spec>;
#[doc = "Filter bank 19 register 1"]
pub mod f19r1;
#[doc = "F19R2 (rw) register accessor: Filter bank 19 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f19r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f19r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f19r2`]
module"]
#[doc(alias = "F19R2")]
pub type F19r2 = crate::Reg<f19r2::F19r2Spec>;
#[doc = "Filter bank 19 register 2"]
pub mod f19r2;
#[doc = "F20R1 (rw) register accessor: Filter bank 20 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f20r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f20r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f20r1`]
module"]
#[doc(alias = "F20R1")]
pub type F20r1 = crate::Reg<f20r1::F20r1Spec>;
#[doc = "Filter bank 20 register 1"]
pub mod f20r1;
#[doc = "F20R2 (rw) register accessor: Filter bank 20 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f20r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f20r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f20r2`]
module"]
#[doc(alias = "F20R2")]
pub type F20r2 = crate::Reg<f20r2::F20r2Spec>;
#[doc = "Filter bank 20 register 2"]
pub mod f20r2;
#[doc = "F21R1 (rw) register accessor: Filter bank 21 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f21r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f21r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f21r1`]
module"]
#[doc(alias = "F21R1")]
pub type F21r1 = crate::Reg<f21r1::F21r1Spec>;
#[doc = "Filter bank 21 register 1"]
pub mod f21r1;
#[doc = "F21R2 (rw) register accessor: Filter bank 21 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f21r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f21r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f21r2`]
module"]
#[doc(alias = "F21R2")]
pub type F21r2 = crate::Reg<f21r2::F21r2Spec>;
#[doc = "Filter bank 21 register 2"]
pub mod f21r2;
#[doc = "F22R1 (rw) register accessor: Filter bank 22 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f22r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f22r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f22r1`]
module"]
#[doc(alias = "F22R1")]
pub type F22r1 = crate::Reg<f22r1::F22r1Spec>;
#[doc = "Filter bank 22 register 1"]
pub mod f22r1;
#[doc = "F22R2 (rw) register accessor: Filter bank 22 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f22r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f22r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f22r2`]
module"]
#[doc(alias = "F22R2")]
pub type F22r2 = crate::Reg<f22r2::F22r2Spec>;
#[doc = "Filter bank 22 register 2"]
pub mod f22r2;
#[doc = "F23R1 (rw) register accessor: Filter bank 23 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f23r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f23r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f23r1`]
module"]
#[doc(alias = "F23R1")]
pub type F23r1 = crate::Reg<f23r1::F23r1Spec>;
#[doc = "Filter bank 23 register 1"]
pub mod f23r1;
#[doc = "F23R2 (rw) register accessor: Filter bank 23 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f23r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f23r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f23r2`]
module"]
#[doc(alias = "F23R2")]
pub type F23r2 = crate::Reg<f23r2::F23r2Spec>;
#[doc = "Filter bank 23 register 2"]
pub mod f23r2;
#[doc = "F24R1 (rw) register accessor: Filter bank 24 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f24r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f24r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f24r1`]
module"]
#[doc(alias = "F24R1")]
pub type F24r1 = crate::Reg<f24r1::F24r1Spec>;
#[doc = "Filter bank 24 register 1"]
pub mod f24r1;
#[doc = "F24R2 (rw) register accessor: Filter bank 24 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f24r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f24r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f24r2`]
module"]
#[doc(alias = "F24R2")]
pub type F24r2 = crate::Reg<f24r2::F24r2Spec>;
#[doc = "Filter bank 24 register 2"]
pub mod f24r2;
#[doc = "F25R1 (rw) register accessor: Filter bank 25 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f25r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f25r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f25r1`]
module"]
#[doc(alias = "F25R1")]
pub type F25r1 = crate::Reg<f25r1::F25r1Spec>;
#[doc = "Filter bank 25 register 1"]
pub mod f25r1;
#[doc = "F25R2 (rw) register accessor: Filter bank 25 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f25r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f25r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f25r2`]
module"]
#[doc(alias = "F25R2")]
pub type F25r2 = crate::Reg<f25r2::F25r2Spec>;
#[doc = "Filter bank 25 register 2"]
pub mod f25r2;
#[doc = "F26R1 (rw) register accessor: Filter bank 26 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f26r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f26r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f26r1`]
module"]
#[doc(alias = "F26R1")]
pub type F26r1 = crate::Reg<f26r1::F26r1Spec>;
#[doc = "Filter bank 26 register 1"]
pub mod f26r1;
#[doc = "F26R2 (rw) register accessor: Filter bank 26 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f26r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f26r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f26r2`]
module"]
#[doc(alias = "F26R2")]
pub type F26r2 = crate::Reg<f26r2::F26r2Spec>;
#[doc = "Filter bank 26 register 2"]
pub mod f26r2;
#[doc = "F27R1 (rw) register accessor: Filter bank 27 register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f27r1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f27r1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f27r1`]
module"]
#[doc(alias = "F27R1")]
pub type F27r1 = crate::Reg<f27r1::F27r1Spec>;
#[doc = "Filter bank 27 register 1"]
pub mod f27r1;
#[doc = "F27R2 (rw) register accessor: Filter bank 27 register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`f27r2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`f27r2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@f27r2`]
module"]
#[doc(alias = "F27R2")]
pub type F27r2 = crate::Reg<f27r2::F27r2Spec>;
#[doc = "Filter bank 27 register 2"]
pub mod f27r2;
