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
    sr: Sr,
    cr1: Cr1,
    cr2: Cr2,
    smpr1: Smpr1,
    smpr2: Smpr2,
    jofr1: Jofr1,
    jofr2: Jofr2,
    jofr3: Jofr3,
    jofr4: Jofr4,
    htr: Htr,
    ltr: Ltr,
    sqr1: Sqr1,
    sqr2: Sqr2,
    sqr3: Sqr3,
    jsqr: Jsqr,
    jdr1: Jdr1,
    jdr2: Jdr2,
    jdr3: Jdr3,
    jdr4: Jdr4,
    dr: Dr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - status register"]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0x04 - control register 1"]
    #[inline(always)]
    pub const fn cr1(&self) -> &Cr1 {
        &self.cr1
    }
    #[doc = "0x08 - control register 2"]
    #[inline(always)]
    pub const fn cr2(&self) -> &Cr2 {
        &self.cr2
    }
    #[doc = "0x0c - sample time register 1"]
    #[inline(always)]
    pub const fn smpr1(&self) -> &Smpr1 {
        &self.smpr1
    }
    #[doc = "0x10 - sample time register 2"]
    #[inline(always)]
    pub const fn smpr2(&self) -> &Smpr2 {
        &self.smpr2
    }
    #[doc = "0x14 - injected channel data offset register x"]
    #[inline(always)]
    pub const fn jofr1(&self) -> &Jofr1 {
        &self.jofr1
    }
    #[doc = "0x18 - injected channel data offset register x"]
    #[inline(always)]
    pub const fn jofr2(&self) -> &Jofr2 {
        &self.jofr2
    }
    #[doc = "0x1c - injected channel data offset register x"]
    #[inline(always)]
    pub const fn jofr3(&self) -> &Jofr3 {
        &self.jofr3
    }
    #[doc = "0x20 - injected channel data offset register x"]
    #[inline(always)]
    pub const fn jofr4(&self) -> &Jofr4 {
        &self.jofr4
    }
    #[doc = "0x24 - watchdog higher threshold register"]
    #[inline(always)]
    pub const fn htr(&self) -> &Htr {
        &self.htr
    }
    #[doc = "0x28 - watchdog lower threshold register"]
    #[inline(always)]
    pub const fn ltr(&self) -> &Ltr {
        &self.ltr
    }
    #[doc = "0x2c - regular sequence register 1"]
    #[inline(always)]
    pub const fn sqr1(&self) -> &Sqr1 {
        &self.sqr1
    }
    #[doc = "0x30 - regular sequence register 2"]
    #[inline(always)]
    pub const fn sqr2(&self) -> &Sqr2 {
        &self.sqr2
    }
    #[doc = "0x34 - regular sequence register 3"]
    #[inline(always)]
    pub const fn sqr3(&self) -> &Sqr3 {
        &self.sqr3
    }
    #[doc = "0x38 - injected sequence register"]
    #[inline(always)]
    pub const fn jsqr(&self) -> &Jsqr {
        &self.jsqr
    }
    #[doc = "0x3c - injected data register x"]
    #[inline(always)]
    pub const fn jdr1(&self) -> &Jdr1 {
        &self.jdr1
    }
    #[doc = "0x40 - injected data register x"]
    #[inline(always)]
    pub const fn jdr2(&self) -> &Jdr2 {
        &self.jdr2
    }
    #[doc = "0x44 - injected data register x"]
    #[inline(always)]
    pub const fn jdr3(&self) -> &Jdr3 {
        &self.jdr3
    }
    #[doc = "0x48 - injected data register x"]
    #[inline(always)]
    pub const fn jdr4(&self) -> &Jdr4 {
        &self.jdr4
    }
    #[doc = "0x4c - regular data register"]
    #[inline(always)]
    pub const fn dr(&self) -> &Dr {
        &self.dr
    }
}
#[doc = "SR (rw) register accessor: status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "SR")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "status register"]
pub mod sr;
#[doc = "CR1 (rw) register accessor: control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr1`]
module"]
#[doc(alias = "CR1")]
pub type Cr1 = crate::Reg<cr1::Cr1Spec>;
#[doc = "control register 1"]
pub mod cr1;
#[doc = "CR2 (rw) register accessor: control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr2`]
module"]
#[doc(alias = "CR2")]
pub type Cr2 = crate::Reg<cr2::Cr2Spec>;
#[doc = "control register 2"]
pub mod cr2;
#[doc = "SMPR1 (rw) register accessor: sample time register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`smpr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`smpr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@smpr1`]
module"]
#[doc(alias = "SMPR1")]
pub type Smpr1 = crate::Reg<smpr1::Smpr1Spec>;
#[doc = "sample time register 1"]
pub mod smpr1;
#[doc = "SMPR2 (rw) register accessor: sample time register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`smpr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`smpr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@smpr2`]
module"]
#[doc(alias = "SMPR2")]
pub type Smpr2 = crate::Reg<smpr2::Smpr2Spec>;
#[doc = "sample time register 2"]
pub mod smpr2;
#[doc = "JOFR1 (rw) register accessor: injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jofr1`]
module"]
#[doc(alias = "JOFR1")]
pub type Jofr1 = crate::Reg<jofr1::Jofr1Spec>;
#[doc = "injected channel data offset register x"]
pub mod jofr1;
#[doc = "JOFR2 (rw) register accessor: injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jofr2`]
module"]
#[doc(alias = "JOFR2")]
pub type Jofr2 = crate::Reg<jofr2::Jofr2Spec>;
#[doc = "injected channel data offset register x"]
pub mod jofr2;
#[doc = "JOFR3 (rw) register accessor: injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jofr3`]
module"]
#[doc(alias = "JOFR3")]
pub type Jofr3 = crate::Reg<jofr3::Jofr3Spec>;
#[doc = "injected channel data offset register x"]
pub mod jofr3;
#[doc = "JOFR4 (rw) register accessor: injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jofr4`]
module"]
#[doc(alias = "JOFR4")]
pub type Jofr4 = crate::Reg<jofr4::Jofr4Spec>;
#[doc = "injected channel data offset register x"]
pub mod jofr4;
#[doc = "HTR (rw) register accessor: watchdog higher threshold register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`htr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`htr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@htr`]
module"]
#[doc(alias = "HTR")]
pub type Htr = crate::Reg<htr::HtrSpec>;
#[doc = "watchdog higher threshold register"]
pub mod htr;
#[doc = "LTR (rw) register accessor: watchdog lower threshold register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ltr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ltr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ltr`]
module"]
#[doc(alias = "LTR")]
pub type Ltr = crate::Reg<ltr::LtrSpec>;
#[doc = "watchdog lower threshold register"]
pub mod ltr;
#[doc = "SQR1 (rw) register accessor: regular sequence register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sqr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sqr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sqr1`]
module"]
#[doc(alias = "SQR1")]
pub type Sqr1 = crate::Reg<sqr1::Sqr1Spec>;
#[doc = "regular sequence register 1"]
pub mod sqr1;
#[doc = "SQR2 (rw) register accessor: regular sequence register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sqr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sqr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sqr2`]
module"]
#[doc(alias = "SQR2")]
pub type Sqr2 = crate::Reg<sqr2::Sqr2Spec>;
#[doc = "regular sequence register 2"]
pub mod sqr2;
#[doc = "SQR3 (rw) register accessor: regular sequence register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sqr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sqr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sqr3`]
module"]
#[doc(alias = "SQR3")]
pub type Sqr3 = crate::Reg<sqr3::Sqr3Spec>;
#[doc = "regular sequence register 3"]
pub mod sqr3;
#[doc = "JSQR (rw) register accessor: injected sequence register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jsqr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jsqr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jsqr`]
module"]
#[doc(alias = "JSQR")]
pub type Jsqr = crate::Reg<jsqr::JsqrSpec>;
#[doc = "injected sequence register"]
pub mod jsqr;
#[doc = "JDR1 (r) register accessor: injected data register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jdr1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jdr1`]
module"]
#[doc(alias = "JDR1")]
pub type Jdr1 = crate::Reg<jdr1::Jdr1Spec>;
#[doc = "injected data register x"]
pub mod jdr1;
#[doc = "JDR2 (r) register accessor: injected data register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jdr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jdr2`]
module"]
#[doc(alias = "JDR2")]
pub type Jdr2 = crate::Reg<jdr2::Jdr2Spec>;
#[doc = "injected data register x"]
pub mod jdr2;
#[doc = "JDR3 (r) register accessor: injected data register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jdr3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jdr3`]
module"]
#[doc(alias = "JDR3")]
pub type Jdr3 = crate::Reg<jdr3::Jdr3Spec>;
#[doc = "injected data register x"]
pub mod jdr3;
#[doc = "JDR4 (r) register accessor: injected data register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jdr4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@jdr4`]
module"]
#[doc(alias = "JDR4")]
pub type Jdr4 = crate::Reg<jdr4::Jdr4Spec>;
#[doc = "injected data register x"]
pub mod jdr4;
#[doc = "DR (r) register accessor: regular data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dr`]
module"]
#[doc(alias = "DR")]
pub type Dr = crate::Reg<dr::DrSpec>;
#[doc = "regular data register"]
pub mod dr;
