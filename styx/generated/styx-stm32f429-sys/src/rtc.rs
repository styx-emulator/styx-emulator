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
    tr: Tr,
    dr: Dr,
    cr: Cr,
    isr: Isr,
    prer: Prer,
    wutr: Wutr,
    calibr: Calibr,
    alrmar: Alrmar,
    alrmbr: Alrmbr,
    wpr: Wpr,
    ssr: Ssr,
    shiftr: Shiftr,
    tstr: Tstr,
    tsdr: Tsdr,
    tsssr: Tsssr,
    calr: Calr,
    tafcr: Tafcr,
    alrmassr: Alrmassr,
    alrmbssr: Alrmbssr,
    _reserved19: [u8; 0x04],
    bkp0r: Bkp0r,
    bkp1r: Bkp1r,
    bkp2r: Bkp2r,
    bkp3r: Bkp3r,
    bkp4r: Bkp4r,
    bkp5r: Bkp5r,
    bkp6r: Bkp6r,
    bkp7r: Bkp7r,
    bkp8r: Bkp8r,
    bkp9r: Bkp9r,
    bkp10r: Bkp10r,
    bkp11r: Bkp11r,
    bkp12r: Bkp12r,
    bkp13r: Bkp13r,
    bkp14r: Bkp14r,
    bkp15r: Bkp15r,
    bkp16r: Bkp16r,
    bkp17r: Bkp17r,
    bkp18r: Bkp18r,
    bkp19r: Bkp19r,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - time register"]
    #[inline(always)]
    pub const fn tr(&self) -> &Tr {
        &self.tr
    }
    #[doc = "0x04 - date register"]
    #[inline(always)]
    pub const fn dr(&self) -> &Dr {
        &self.dr
    }
    #[doc = "0x08 - control register"]
    #[inline(always)]
    pub const fn cr(&self) -> &Cr {
        &self.cr
    }
    #[doc = "0x0c - initialization and status register"]
    #[inline(always)]
    pub const fn isr(&self) -> &Isr {
        &self.isr
    }
    #[doc = "0x10 - prescaler register"]
    #[inline(always)]
    pub const fn prer(&self) -> &Prer {
        &self.prer
    }
    #[doc = "0x14 - wakeup timer register"]
    #[inline(always)]
    pub const fn wutr(&self) -> &Wutr {
        &self.wutr
    }
    #[doc = "0x18 - calibration register"]
    #[inline(always)]
    pub const fn calibr(&self) -> &Calibr {
        &self.calibr
    }
    #[doc = "0x1c - alarm A register"]
    #[inline(always)]
    pub const fn alrmar(&self) -> &Alrmar {
        &self.alrmar
    }
    #[doc = "0x20 - alarm B register"]
    #[inline(always)]
    pub const fn alrmbr(&self) -> &Alrmbr {
        &self.alrmbr
    }
    #[doc = "0x24 - write protection register"]
    #[inline(always)]
    pub const fn wpr(&self) -> &Wpr {
        &self.wpr
    }
    #[doc = "0x28 - sub second register"]
    #[inline(always)]
    pub const fn ssr(&self) -> &Ssr {
        &self.ssr
    }
    #[doc = "0x2c - shift control register"]
    #[inline(always)]
    pub const fn shiftr(&self) -> &Shiftr {
        &self.shiftr
    }
    #[doc = "0x30 - time stamp time register"]
    #[inline(always)]
    pub const fn tstr(&self) -> &Tstr {
        &self.tstr
    }
    #[doc = "0x34 - time stamp date register"]
    #[inline(always)]
    pub const fn tsdr(&self) -> &Tsdr {
        &self.tsdr
    }
    #[doc = "0x38 - timestamp sub second register"]
    #[inline(always)]
    pub const fn tsssr(&self) -> &Tsssr {
        &self.tsssr
    }
    #[doc = "0x3c - calibration register"]
    #[inline(always)]
    pub const fn calr(&self) -> &Calr {
        &self.calr
    }
    #[doc = "0x40 - tamper and alternate function configuration register"]
    #[inline(always)]
    pub const fn tafcr(&self) -> &Tafcr {
        &self.tafcr
    }
    #[doc = "0x44 - alarm A sub second register"]
    #[inline(always)]
    pub const fn alrmassr(&self) -> &Alrmassr {
        &self.alrmassr
    }
    #[doc = "0x48 - alarm B sub second register"]
    #[inline(always)]
    pub const fn alrmbssr(&self) -> &Alrmbssr {
        &self.alrmbssr
    }
    #[doc = "0x50 - backup register"]
    #[inline(always)]
    pub const fn bkp0r(&self) -> &Bkp0r {
        &self.bkp0r
    }
    #[doc = "0x54 - backup register"]
    #[inline(always)]
    pub const fn bkp1r(&self) -> &Bkp1r {
        &self.bkp1r
    }
    #[doc = "0x58 - backup register"]
    #[inline(always)]
    pub const fn bkp2r(&self) -> &Bkp2r {
        &self.bkp2r
    }
    #[doc = "0x5c - backup register"]
    #[inline(always)]
    pub const fn bkp3r(&self) -> &Bkp3r {
        &self.bkp3r
    }
    #[doc = "0x60 - backup register"]
    #[inline(always)]
    pub const fn bkp4r(&self) -> &Bkp4r {
        &self.bkp4r
    }
    #[doc = "0x64 - backup register"]
    #[inline(always)]
    pub const fn bkp5r(&self) -> &Bkp5r {
        &self.bkp5r
    }
    #[doc = "0x68 - backup register"]
    #[inline(always)]
    pub const fn bkp6r(&self) -> &Bkp6r {
        &self.bkp6r
    }
    #[doc = "0x6c - backup register"]
    #[inline(always)]
    pub const fn bkp7r(&self) -> &Bkp7r {
        &self.bkp7r
    }
    #[doc = "0x70 - backup register"]
    #[inline(always)]
    pub const fn bkp8r(&self) -> &Bkp8r {
        &self.bkp8r
    }
    #[doc = "0x74 - backup register"]
    #[inline(always)]
    pub const fn bkp9r(&self) -> &Bkp9r {
        &self.bkp9r
    }
    #[doc = "0x78 - backup register"]
    #[inline(always)]
    pub const fn bkp10r(&self) -> &Bkp10r {
        &self.bkp10r
    }
    #[doc = "0x7c - backup register"]
    #[inline(always)]
    pub const fn bkp11r(&self) -> &Bkp11r {
        &self.bkp11r
    }
    #[doc = "0x80 - backup register"]
    #[inline(always)]
    pub const fn bkp12r(&self) -> &Bkp12r {
        &self.bkp12r
    }
    #[doc = "0x84 - backup register"]
    #[inline(always)]
    pub const fn bkp13r(&self) -> &Bkp13r {
        &self.bkp13r
    }
    #[doc = "0x88 - backup register"]
    #[inline(always)]
    pub const fn bkp14r(&self) -> &Bkp14r {
        &self.bkp14r
    }
    #[doc = "0x8c - backup register"]
    #[inline(always)]
    pub const fn bkp15r(&self) -> &Bkp15r {
        &self.bkp15r
    }
    #[doc = "0x90 - backup register"]
    #[inline(always)]
    pub const fn bkp16r(&self) -> &Bkp16r {
        &self.bkp16r
    }
    #[doc = "0x94 - backup register"]
    #[inline(always)]
    pub const fn bkp17r(&self) -> &Bkp17r {
        &self.bkp17r
    }
    #[doc = "0x98 - backup register"]
    #[inline(always)]
    pub const fn bkp18r(&self) -> &Bkp18r {
        &self.bkp18r
    }
    #[doc = "0x9c - backup register"]
    #[inline(always)]
    pub const fn bkp19r(&self) -> &Bkp19r {
        &self.bkp19r
    }
}
#[doc = "TR (rw) register accessor: time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tr`]
module"]
#[doc(alias = "TR")]
pub type Tr = crate::Reg<tr::TrSpec>;
#[doc = "time register"]
pub mod tr;
#[doc = "DR (rw) register accessor: date register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dr`]
module"]
#[doc(alias = "DR")]
pub type Dr = crate::Reg<dr::DrSpec>;
#[doc = "date register"]
pub mod dr;
#[doc = "CR (rw) register accessor: control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr`]
module"]
#[doc(alias = "CR")]
pub type Cr = crate::Reg<cr::CrSpec>;
#[doc = "control register"]
pub mod cr;
#[doc = "ISR (rw) register accessor: initialization and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`isr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@isr`]
module"]
#[doc(alias = "ISR")]
pub type Isr = crate::Reg<isr::IsrSpec>;
#[doc = "initialization and status register"]
pub mod isr;
#[doc = "PRER (rw) register accessor: prescaler register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`prer::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`prer::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@prer`]
module"]
#[doc(alias = "PRER")]
pub type Prer = crate::Reg<prer::PrerSpec>;
#[doc = "prescaler register"]
pub mod prer;
#[doc = "WUTR (rw) register accessor: wakeup timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wutr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wutr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wutr`]
module"]
#[doc(alias = "WUTR")]
pub type Wutr = crate::Reg<wutr::WutrSpec>;
#[doc = "wakeup timer register"]
pub mod wutr;
#[doc = "CALIBR (rw) register accessor: calibration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`calibr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`calibr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@calibr`]
module"]
#[doc(alias = "CALIBR")]
pub type Calibr = crate::Reg<calibr::CalibrSpec>;
#[doc = "calibration register"]
pub mod calibr;
#[doc = "ALRMAR (rw) register accessor: alarm A register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`alrmar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`alrmar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@alrmar`]
module"]
#[doc(alias = "ALRMAR")]
pub type Alrmar = crate::Reg<alrmar::AlrmarSpec>;
#[doc = "alarm A register"]
pub mod alrmar;
#[doc = "ALRMBR (rw) register accessor: alarm B register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`alrmbr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`alrmbr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@alrmbr`]
module"]
#[doc(alias = "ALRMBR")]
pub type Alrmbr = crate::Reg<alrmbr::AlrmbrSpec>;
#[doc = "alarm B register"]
pub mod alrmbr;
#[doc = "WPR (w) register accessor: write protection register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wpr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wpr`]
module"]
#[doc(alias = "WPR")]
pub type Wpr = crate::Reg<wpr::WprSpec>;
#[doc = "write protection register"]
pub mod wpr;
#[doc = "SSR (r) register accessor: sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ssr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ssr`]
module"]
#[doc(alias = "SSR")]
pub type Ssr = crate::Reg<ssr::SsrSpec>;
#[doc = "sub second register"]
pub mod ssr;
#[doc = "SHIFTR (w) register accessor: shift control register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`shiftr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@shiftr`]
module"]
#[doc(alias = "SHIFTR")]
pub type Shiftr = crate::Reg<shiftr::ShiftrSpec>;
#[doc = "shift control register"]
pub mod shiftr;
#[doc = "TSTR (r) register accessor: time stamp time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tstr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tstr`]
module"]
#[doc(alias = "TSTR")]
pub type Tstr = crate::Reg<tstr::TstrSpec>;
#[doc = "time stamp time register"]
pub mod tstr;
#[doc = "TSDR (r) register accessor: time stamp date register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tsdr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tsdr`]
module"]
#[doc(alias = "TSDR")]
pub type Tsdr = crate::Reg<tsdr::TsdrSpec>;
#[doc = "time stamp date register"]
pub mod tsdr;
#[doc = "TSSSR (r) register accessor: timestamp sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tsssr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tsssr`]
module"]
#[doc(alias = "TSSSR")]
pub type Tsssr = crate::Reg<tsssr::TsssrSpec>;
#[doc = "timestamp sub second register"]
pub mod tsssr;
#[doc = "CALR (rw) register accessor: calibration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`calr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`calr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@calr`]
module"]
#[doc(alias = "CALR")]
pub type Calr = crate::Reg<calr::CalrSpec>;
#[doc = "calibration register"]
pub mod calr;
#[doc = "TAFCR (rw) register accessor: tamper and alternate function configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tafcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tafcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tafcr`]
module"]
#[doc(alias = "TAFCR")]
pub type Tafcr = crate::Reg<tafcr::TafcrSpec>;
#[doc = "tamper and alternate function configuration register"]
pub mod tafcr;
#[doc = "ALRMASSR (rw) register accessor: alarm A sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`alrmassr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`alrmassr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@alrmassr`]
module"]
#[doc(alias = "ALRMASSR")]
pub type Alrmassr = crate::Reg<alrmassr::AlrmassrSpec>;
#[doc = "alarm A sub second register"]
pub mod alrmassr;
#[doc = "ALRMBSSR (rw) register accessor: alarm B sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`alrmbssr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`alrmbssr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@alrmbssr`]
module"]
#[doc(alias = "ALRMBSSR")]
pub type Alrmbssr = crate::Reg<alrmbssr::AlrmbssrSpec>;
#[doc = "alarm B sub second register"]
pub mod alrmbssr;
#[doc = "BKP0R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp0r`]
module"]
#[doc(alias = "BKP0R")]
pub type Bkp0r = crate::Reg<bkp0r::Bkp0rSpec>;
#[doc = "backup register"]
pub mod bkp0r;
#[doc = "BKP1R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp1r`]
module"]
#[doc(alias = "BKP1R")]
pub type Bkp1r = crate::Reg<bkp1r::Bkp1rSpec>;
#[doc = "backup register"]
pub mod bkp1r;
#[doc = "BKP2R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp2r`]
module"]
#[doc(alias = "BKP2R")]
pub type Bkp2r = crate::Reg<bkp2r::Bkp2rSpec>;
#[doc = "backup register"]
pub mod bkp2r;
#[doc = "BKP3R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp3r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp3r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp3r`]
module"]
#[doc(alias = "BKP3R")]
pub type Bkp3r = crate::Reg<bkp3r::Bkp3rSpec>;
#[doc = "backup register"]
pub mod bkp3r;
#[doc = "BKP4R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp4r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp4r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp4r`]
module"]
#[doc(alias = "BKP4R")]
pub type Bkp4r = crate::Reg<bkp4r::Bkp4rSpec>;
#[doc = "backup register"]
pub mod bkp4r;
#[doc = "BKP5R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp5r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp5r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp5r`]
module"]
#[doc(alias = "BKP5R")]
pub type Bkp5r = crate::Reg<bkp5r::Bkp5rSpec>;
#[doc = "backup register"]
pub mod bkp5r;
#[doc = "BKP6R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp6r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp6r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp6r`]
module"]
#[doc(alias = "BKP6R")]
pub type Bkp6r = crate::Reg<bkp6r::Bkp6rSpec>;
#[doc = "backup register"]
pub mod bkp6r;
#[doc = "BKP7R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp7r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp7r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp7r`]
module"]
#[doc(alias = "BKP7R")]
pub type Bkp7r = crate::Reg<bkp7r::Bkp7rSpec>;
#[doc = "backup register"]
pub mod bkp7r;
#[doc = "BKP8R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp8r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp8r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp8r`]
module"]
#[doc(alias = "BKP8R")]
pub type Bkp8r = crate::Reg<bkp8r::Bkp8rSpec>;
#[doc = "backup register"]
pub mod bkp8r;
#[doc = "BKP9R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp9r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp9r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp9r`]
module"]
#[doc(alias = "BKP9R")]
pub type Bkp9r = crate::Reg<bkp9r::Bkp9rSpec>;
#[doc = "backup register"]
pub mod bkp9r;
#[doc = "BKP10R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp10r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp10r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp10r`]
module"]
#[doc(alias = "BKP10R")]
pub type Bkp10r = crate::Reg<bkp10r::Bkp10rSpec>;
#[doc = "backup register"]
pub mod bkp10r;
#[doc = "BKP11R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp11r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp11r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp11r`]
module"]
#[doc(alias = "BKP11R")]
pub type Bkp11r = crate::Reg<bkp11r::Bkp11rSpec>;
#[doc = "backup register"]
pub mod bkp11r;
#[doc = "BKP12R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp12r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp12r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp12r`]
module"]
#[doc(alias = "BKP12R")]
pub type Bkp12r = crate::Reg<bkp12r::Bkp12rSpec>;
#[doc = "backup register"]
pub mod bkp12r;
#[doc = "BKP13R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp13r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp13r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp13r`]
module"]
#[doc(alias = "BKP13R")]
pub type Bkp13r = crate::Reg<bkp13r::Bkp13rSpec>;
#[doc = "backup register"]
pub mod bkp13r;
#[doc = "BKP14R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp14r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp14r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp14r`]
module"]
#[doc(alias = "BKP14R")]
pub type Bkp14r = crate::Reg<bkp14r::Bkp14rSpec>;
#[doc = "backup register"]
pub mod bkp14r;
#[doc = "BKP15R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp15r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp15r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp15r`]
module"]
#[doc(alias = "BKP15R")]
pub type Bkp15r = crate::Reg<bkp15r::Bkp15rSpec>;
#[doc = "backup register"]
pub mod bkp15r;
#[doc = "BKP16R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp16r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp16r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp16r`]
module"]
#[doc(alias = "BKP16R")]
pub type Bkp16r = crate::Reg<bkp16r::Bkp16rSpec>;
#[doc = "backup register"]
pub mod bkp16r;
#[doc = "BKP17R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp17r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp17r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp17r`]
module"]
#[doc(alias = "BKP17R")]
pub type Bkp17r = crate::Reg<bkp17r::Bkp17rSpec>;
#[doc = "backup register"]
pub mod bkp17r;
#[doc = "BKP18R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp18r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp18r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp18r`]
module"]
#[doc(alias = "BKP18R")]
pub type Bkp18r = crate::Reg<bkp18r::Bkp18rSpec>;
#[doc = "backup register"]
pub mod bkp18r;
#[doc = "BKP19R (rw) register accessor: backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp19r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp19r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bkp19r`]
module"]
#[doc(alias = "BKP19R")]
pub type Bkp19r = crate::Reg<bkp19r::Bkp19rSpec>;
#[doc = "backup register"]
pub mod bkp19r;
