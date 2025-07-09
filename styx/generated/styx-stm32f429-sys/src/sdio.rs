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
    power: Power,
    clkcr: Clkcr,
    arg: Arg,
    cmd: Cmd,
    respcmd: Respcmd,
    resp1: Resp1,
    resp2: Resp2,
    resp3: Resp3,
    resp4: Resp4,
    dtimer: Dtimer,
    dlen: Dlen,
    dctrl: Dctrl,
    dcount: Dcount,
    sta: Sta,
    icr: Icr,
    mask: Mask,
    _reserved16: [u8; 0x08],
    fifocnt: Fifocnt,
    _reserved17: [u8; 0x34],
    fifo: Fifo,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - power control register"]
    #[inline(always)]
    pub const fn power(&self) -> &Power {
        &self.power
    }
    #[doc = "0x04 - SDI clock control register"]
    #[inline(always)]
    pub const fn clkcr(&self) -> &Clkcr {
        &self.clkcr
    }
    #[doc = "0x08 - argument register"]
    #[inline(always)]
    pub const fn arg(&self) -> &Arg {
        &self.arg
    }
    #[doc = "0x0c - command register"]
    #[inline(always)]
    pub const fn cmd(&self) -> &Cmd {
        &self.cmd
    }
    #[doc = "0x10 - command response register"]
    #[inline(always)]
    pub const fn respcmd(&self) -> &Respcmd {
        &self.respcmd
    }
    #[doc = "0x14 - response 1..4 register"]
    #[inline(always)]
    pub const fn resp1(&self) -> &Resp1 {
        &self.resp1
    }
    #[doc = "0x18 - response 1..4 register"]
    #[inline(always)]
    pub const fn resp2(&self) -> &Resp2 {
        &self.resp2
    }
    #[doc = "0x1c - response 1..4 register"]
    #[inline(always)]
    pub const fn resp3(&self) -> &Resp3 {
        &self.resp3
    }
    #[doc = "0x20 - response 1..4 register"]
    #[inline(always)]
    pub const fn resp4(&self) -> &Resp4 {
        &self.resp4
    }
    #[doc = "0x24 - data timer register"]
    #[inline(always)]
    pub const fn dtimer(&self) -> &Dtimer {
        &self.dtimer
    }
    #[doc = "0x28 - data length register"]
    #[inline(always)]
    pub const fn dlen(&self) -> &Dlen {
        &self.dlen
    }
    #[doc = "0x2c - data control register"]
    #[inline(always)]
    pub const fn dctrl(&self) -> &Dctrl {
        &self.dctrl
    }
    #[doc = "0x30 - data counter register"]
    #[inline(always)]
    pub const fn dcount(&self) -> &Dcount {
        &self.dcount
    }
    #[doc = "0x34 - status register"]
    #[inline(always)]
    pub const fn sta(&self) -> &Sta {
        &self.sta
    }
    #[doc = "0x38 - interrupt clear register"]
    #[inline(always)]
    pub const fn icr(&self) -> &Icr {
        &self.icr
    }
    #[doc = "0x3c - mask register"]
    #[inline(always)]
    pub const fn mask(&self) -> &Mask {
        &self.mask
    }
    #[doc = "0x48 - FIFO counter register"]
    #[inline(always)]
    pub const fn fifocnt(&self) -> &Fifocnt {
        &self.fifocnt
    }
    #[doc = "0x80 - data FIFO register"]
    #[inline(always)]
    pub const fn fifo(&self) -> &Fifo {
        &self.fifo
    }
}
#[doc = "POWER (rw) register accessor: power control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`power::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`power::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@power`]
module"]
#[doc(alias = "POWER")]
pub type Power = crate::Reg<power::PowerSpec>;
#[doc = "power control register"]
pub mod power;
#[doc = "CLKCR (rw) register accessor: SDI clock control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clkcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clkcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@clkcr`]
module"]
#[doc(alias = "CLKCR")]
pub type Clkcr = crate::Reg<clkcr::ClkcrSpec>;
#[doc = "SDI clock control register"]
pub mod clkcr;
#[doc = "ARG (rw) register accessor: argument register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`arg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`arg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@arg`]
module"]
#[doc(alias = "ARG")]
pub type Arg = crate::Reg<arg::ArgSpec>;
#[doc = "argument register"]
pub mod arg;
#[doc = "CMD (rw) register accessor: command register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cmd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cmd`]
module"]
#[doc(alias = "CMD")]
pub type Cmd = crate::Reg<cmd::CmdSpec>;
#[doc = "command register"]
pub mod cmd;
#[doc = "RESPCMD (r) register accessor: command response register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`respcmd::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@respcmd`]
module"]
#[doc(alias = "RESPCMD")]
pub type Respcmd = crate::Reg<respcmd::RespcmdSpec>;
#[doc = "command response register"]
pub mod respcmd;
#[doc = "RESP1 (r) register accessor: response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp1`]
module"]
#[doc(alias = "RESP1")]
pub type Resp1 = crate::Reg<resp1::Resp1Spec>;
#[doc = "response 1..4 register"]
pub mod resp1;
#[doc = "RESP2 (r) register accessor: response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp2`]
module"]
#[doc(alias = "RESP2")]
pub type Resp2 = crate::Reg<resp2::Resp2Spec>;
#[doc = "response 1..4 register"]
pub mod resp2;
#[doc = "RESP3 (r) register accessor: response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp3`]
module"]
#[doc(alias = "RESP3")]
pub type Resp3 = crate::Reg<resp3::Resp3Spec>;
#[doc = "response 1..4 register"]
pub mod resp3;
#[doc = "RESP4 (r) register accessor: response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp4`]
module"]
#[doc(alias = "RESP4")]
pub type Resp4 = crate::Reg<resp4::Resp4Spec>;
#[doc = "response 1..4 register"]
pub mod resp4;
#[doc = "DTIMER (rw) register accessor: data timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtimer::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dtimer::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dtimer`]
module"]
#[doc(alias = "DTIMER")]
pub type Dtimer = crate::Reg<dtimer::DtimerSpec>;
#[doc = "data timer register"]
pub mod dtimer;
#[doc = "DLEN (rw) register accessor: data length register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dlen::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dlen::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dlen`]
module"]
#[doc(alias = "DLEN")]
pub type Dlen = crate::Reg<dlen::DlenSpec>;
#[doc = "data length register"]
pub mod dlen;
#[doc = "DCTRL (rw) register accessor: data control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dctrl`]
module"]
#[doc(alias = "DCTRL")]
pub type Dctrl = crate::Reg<dctrl::DctrlSpec>;
#[doc = "data control register"]
pub mod dctrl;
#[doc = "DCOUNT (r) register accessor: data counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dcount::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dcount`]
module"]
#[doc(alias = "DCOUNT")]
pub type Dcount = crate::Reg<dcount::DcountSpec>;
#[doc = "data counter register"]
pub mod dcount;
#[doc = "STA (r) register accessor: status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sta::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sta`]
module"]
#[doc(alias = "STA")]
pub type Sta = crate::Reg<sta::StaSpec>;
#[doc = "status register"]
pub mod sta;
#[doc = "ICR (rw) register accessor: interrupt clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icr`]
module"]
#[doc(alias = "ICR")]
pub type Icr = crate::Reg<icr::IcrSpec>;
#[doc = "interrupt clear register"]
pub mod icr;
#[doc = "MASK (rw) register accessor: mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mask`]
module"]
#[doc(alias = "MASK")]
pub type Mask = crate::Reg<mask::MaskSpec>;
#[doc = "mask register"]
pub mod mask;
#[doc = "FIFOCNT (r) register accessor: FIFO counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifocnt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifocnt`]
module"]
#[doc(alias = "FIFOCNT")]
pub type Fifocnt = crate::Reg<fifocnt::FifocntSpec>;
#[doc = "FIFO counter register"]
pub mod fifocnt;
#[doc = "FIFO (rw) register accessor: data FIFO register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifo::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifo::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifo`]
module"]
#[doc(alias = "FIFO")]
pub type Fifo = crate::Reg<fifo::FifoSpec>;
#[doc = "data FIFO register"]
pub mod fifo;
