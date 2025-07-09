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
    lisr: Lisr,
    hisr: Hisr,
    lifcr: Lifcr,
    hifcr: Hifcr,
    s0cr: S0cr,
    s0ndtr: S0ndtr,
    s0par: S0par,
    s0m0ar: S0m0ar,
    s0m1ar: S0m1ar,
    s0fcr: S0fcr,
    s1cr: S1cr,
    s1ndtr: S1ndtr,
    s1par: S1par,
    s1m0ar: S1m0ar,
    s1m1ar: S1m1ar,
    s1fcr: S1fcr,
    s2cr: S2cr,
    s2ndtr: S2ndtr,
    s2par: S2par,
    s2m0ar: S2m0ar,
    s2m1ar: S2m1ar,
    s2fcr: S2fcr,
    s3cr: S3cr,
    s3ndtr: S3ndtr,
    s3par: S3par,
    s3m0ar: S3m0ar,
    s3m1ar: S3m1ar,
    s3fcr: S3fcr,
    s4cr: S4cr,
    s4ndtr: S4ndtr,
    s4par: S4par,
    s4m0ar: S4m0ar,
    s4m1ar: S4m1ar,
    s4fcr: S4fcr,
    s5cr: S5cr,
    s5ndtr: S5ndtr,
    s5par: S5par,
    s5m0ar: S5m0ar,
    s5m1ar: S5m1ar,
    s5fcr: S5fcr,
    s6cr: S6cr,
    s6ndtr: S6ndtr,
    s6par: S6par,
    s6m0ar: S6m0ar,
    s6m1ar: S6m1ar,
    s6fcr: S6fcr,
    s7cr: S7cr,
    s7ndtr: S7ndtr,
    s7par: S7par,
    s7m0ar: S7m0ar,
    s7m1ar: S7m1ar,
    s7fcr: S7fcr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - low interrupt status register"]
    #[inline(always)]
    pub const fn lisr(&self) -> &Lisr {
        &self.lisr
    }
    #[doc = "0x04 - high interrupt status register"]
    #[inline(always)]
    pub const fn hisr(&self) -> &Hisr {
        &self.hisr
    }
    #[doc = "0x08 - low interrupt flag clear register"]
    #[inline(always)]
    pub const fn lifcr(&self) -> &Lifcr {
        &self.lifcr
    }
    #[doc = "0x0c - high interrupt flag clear register"]
    #[inline(always)]
    pub const fn hifcr(&self) -> &Hifcr {
        &self.hifcr
    }
    #[doc = "0x10 - stream x configuration register"]
    #[inline(always)]
    pub const fn s0cr(&self) -> &S0cr {
        &self.s0cr
    }
    #[doc = "0x14 - stream x number of data register"]
    #[inline(always)]
    pub const fn s0ndtr(&self) -> &S0ndtr {
        &self.s0ndtr
    }
    #[doc = "0x18 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s0par(&self) -> &S0par {
        &self.s0par
    }
    #[doc = "0x1c - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s0m0ar(&self) -> &S0m0ar {
        &self.s0m0ar
    }
    #[doc = "0x20 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s0m1ar(&self) -> &S0m1ar {
        &self.s0m1ar
    }
    #[doc = "0x24 - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s0fcr(&self) -> &S0fcr {
        &self.s0fcr
    }
    #[doc = "0x28 - stream x configuration register"]
    #[inline(always)]
    pub const fn s1cr(&self) -> &S1cr {
        &self.s1cr
    }
    #[doc = "0x2c - stream x number of data register"]
    #[inline(always)]
    pub const fn s1ndtr(&self) -> &S1ndtr {
        &self.s1ndtr
    }
    #[doc = "0x30 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s1par(&self) -> &S1par {
        &self.s1par
    }
    #[doc = "0x34 - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s1m0ar(&self) -> &S1m0ar {
        &self.s1m0ar
    }
    #[doc = "0x38 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s1m1ar(&self) -> &S1m1ar {
        &self.s1m1ar
    }
    #[doc = "0x3c - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s1fcr(&self) -> &S1fcr {
        &self.s1fcr
    }
    #[doc = "0x40 - stream x configuration register"]
    #[inline(always)]
    pub const fn s2cr(&self) -> &S2cr {
        &self.s2cr
    }
    #[doc = "0x44 - stream x number of data register"]
    #[inline(always)]
    pub const fn s2ndtr(&self) -> &S2ndtr {
        &self.s2ndtr
    }
    #[doc = "0x48 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s2par(&self) -> &S2par {
        &self.s2par
    }
    #[doc = "0x4c - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s2m0ar(&self) -> &S2m0ar {
        &self.s2m0ar
    }
    #[doc = "0x50 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s2m1ar(&self) -> &S2m1ar {
        &self.s2m1ar
    }
    #[doc = "0x54 - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s2fcr(&self) -> &S2fcr {
        &self.s2fcr
    }
    #[doc = "0x58 - stream x configuration register"]
    #[inline(always)]
    pub const fn s3cr(&self) -> &S3cr {
        &self.s3cr
    }
    #[doc = "0x5c - stream x number of data register"]
    #[inline(always)]
    pub const fn s3ndtr(&self) -> &S3ndtr {
        &self.s3ndtr
    }
    #[doc = "0x60 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s3par(&self) -> &S3par {
        &self.s3par
    }
    #[doc = "0x64 - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s3m0ar(&self) -> &S3m0ar {
        &self.s3m0ar
    }
    #[doc = "0x68 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s3m1ar(&self) -> &S3m1ar {
        &self.s3m1ar
    }
    #[doc = "0x6c - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s3fcr(&self) -> &S3fcr {
        &self.s3fcr
    }
    #[doc = "0x70 - stream x configuration register"]
    #[inline(always)]
    pub const fn s4cr(&self) -> &S4cr {
        &self.s4cr
    }
    #[doc = "0x74 - stream x number of data register"]
    #[inline(always)]
    pub const fn s4ndtr(&self) -> &S4ndtr {
        &self.s4ndtr
    }
    #[doc = "0x78 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s4par(&self) -> &S4par {
        &self.s4par
    }
    #[doc = "0x7c - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s4m0ar(&self) -> &S4m0ar {
        &self.s4m0ar
    }
    #[doc = "0x80 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s4m1ar(&self) -> &S4m1ar {
        &self.s4m1ar
    }
    #[doc = "0x84 - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s4fcr(&self) -> &S4fcr {
        &self.s4fcr
    }
    #[doc = "0x88 - stream x configuration register"]
    #[inline(always)]
    pub const fn s5cr(&self) -> &S5cr {
        &self.s5cr
    }
    #[doc = "0x8c - stream x number of data register"]
    #[inline(always)]
    pub const fn s5ndtr(&self) -> &S5ndtr {
        &self.s5ndtr
    }
    #[doc = "0x90 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s5par(&self) -> &S5par {
        &self.s5par
    }
    #[doc = "0x94 - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s5m0ar(&self) -> &S5m0ar {
        &self.s5m0ar
    }
    #[doc = "0x98 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s5m1ar(&self) -> &S5m1ar {
        &self.s5m1ar
    }
    #[doc = "0x9c - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s5fcr(&self) -> &S5fcr {
        &self.s5fcr
    }
    #[doc = "0xa0 - stream x configuration register"]
    #[inline(always)]
    pub const fn s6cr(&self) -> &S6cr {
        &self.s6cr
    }
    #[doc = "0xa4 - stream x number of data register"]
    #[inline(always)]
    pub const fn s6ndtr(&self) -> &S6ndtr {
        &self.s6ndtr
    }
    #[doc = "0xa8 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s6par(&self) -> &S6par {
        &self.s6par
    }
    #[doc = "0xac - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s6m0ar(&self) -> &S6m0ar {
        &self.s6m0ar
    }
    #[doc = "0xb0 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s6m1ar(&self) -> &S6m1ar {
        &self.s6m1ar
    }
    #[doc = "0xb4 - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s6fcr(&self) -> &S6fcr {
        &self.s6fcr
    }
    #[doc = "0xb8 - stream x configuration register"]
    #[inline(always)]
    pub const fn s7cr(&self) -> &S7cr {
        &self.s7cr
    }
    #[doc = "0xbc - stream x number of data register"]
    #[inline(always)]
    pub const fn s7ndtr(&self) -> &S7ndtr {
        &self.s7ndtr
    }
    #[doc = "0xc0 - stream x peripheral address register"]
    #[inline(always)]
    pub const fn s7par(&self) -> &S7par {
        &self.s7par
    }
    #[doc = "0xc4 - stream x memory 0 address register"]
    #[inline(always)]
    pub const fn s7m0ar(&self) -> &S7m0ar {
        &self.s7m0ar
    }
    #[doc = "0xc8 - stream x memory 1 address register"]
    #[inline(always)]
    pub const fn s7m1ar(&self) -> &S7m1ar {
        &self.s7m1ar
    }
    #[doc = "0xcc - stream x FIFO control register"]
    #[inline(always)]
    pub const fn s7fcr(&self) -> &S7fcr {
        &self.s7fcr
    }
}
#[doc = "LISR (r) register accessor: low interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lisr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lisr`]
module"]
#[doc(alias = "LISR")]
pub type Lisr = crate::Reg<lisr::LisrSpec>;
#[doc = "low interrupt status register"]
pub mod lisr;
#[doc = "HISR (r) register accessor: high interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hisr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hisr`]
module"]
#[doc(alias = "HISR")]
pub type Hisr = crate::Reg<hisr::HisrSpec>;
#[doc = "high interrupt status register"]
pub mod hisr;
#[doc = "LIFCR (rw) register accessor: low interrupt flag clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lifcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lifcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lifcr`]
module"]
#[doc(alias = "LIFCR")]
pub type Lifcr = crate::Reg<lifcr::LifcrSpec>;
#[doc = "low interrupt flag clear register"]
pub mod lifcr;
#[doc = "HIFCR (rw) register accessor: high interrupt flag clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hifcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hifcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hifcr`]
module"]
#[doc(alias = "HIFCR")]
pub type Hifcr = crate::Reg<hifcr::HifcrSpec>;
#[doc = "high interrupt flag clear register"]
pub mod hifcr;
#[doc = "S0CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s0cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s0cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s0cr`]
module"]
#[doc(alias = "S0CR")]
pub type S0cr = crate::Reg<s0cr::S0crSpec>;
#[doc = "stream x configuration register"]
pub mod s0cr;
#[doc = "S0NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s0ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s0ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s0ndtr`]
module"]
#[doc(alias = "S0NDTR")]
pub type S0ndtr = crate::Reg<s0ndtr::S0ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s0ndtr;
#[doc = "S0PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s0par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s0par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s0par`]
module"]
#[doc(alias = "S0PAR")]
pub type S0par = crate::Reg<s0par::S0parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s0par;
#[doc = "S0M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s0m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s0m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s0m0ar`]
module"]
#[doc(alias = "S0M0AR")]
pub type S0m0ar = crate::Reg<s0m0ar::S0m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s0m0ar;
#[doc = "S0M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s0m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s0m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s0m1ar`]
module"]
#[doc(alias = "S0M1AR")]
pub type S0m1ar = crate::Reg<s0m1ar::S0m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s0m1ar;
#[doc = "S0FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s0fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s0fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s0fcr`]
module"]
#[doc(alias = "S0FCR")]
pub type S0fcr = crate::Reg<s0fcr::S0fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s0fcr;
#[doc = "S1CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s1cr`]
module"]
#[doc(alias = "S1CR")]
pub type S1cr = crate::Reg<s1cr::S1crSpec>;
#[doc = "stream x configuration register"]
pub mod s1cr;
#[doc = "S1NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s1ndtr`]
module"]
#[doc(alias = "S1NDTR")]
pub type S1ndtr = crate::Reg<s1ndtr::S1ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s1ndtr;
#[doc = "S1PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s1par`]
module"]
#[doc(alias = "S1PAR")]
pub type S1par = crate::Reg<s1par::S1parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s1par;
#[doc = "S1M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s1m0ar`]
module"]
#[doc(alias = "S1M0AR")]
pub type S1m0ar = crate::Reg<s1m0ar::S1m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s1m0ar;
#[doc = "S1M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s1m1ar`]
module"]
#[doc(alias = "S1M1AR")]
pub type S1m1ar = crate::Reg<s1m1ar::S1m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s1m1ar;
#[doc = "S1FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s1fcr`]
module"]
#[doc(alias = "S1FCR")]
pub type S1fcr = crate::Reg<s1fcr::S1fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s1fcr;
#[doc = "S2CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s2cr`]
module"]
#[doc(alias = "S2CR")]
pub type S2cr = crate::Reg<s2cr::S2crSpec>;
#[doc = "stream x configuration register"]
pub mod s2cr;
#[doc = "S2NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s2ndtr`]
module"]
#[doc(alias = "S2NDTR")]
pub type S2ndtr = crate::Reg<s2ndtr::S2ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s2ndtr;
#[doc = "S2PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s2par`]
module"]
#[doc(alias = "S2PAR")]
pub type S2par = crate::Reg<s2par::S2parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s2par;
#[doc = "S2M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s2m0ar`]
module"]
#[doc(alias = "S2M0AR")]
pub type S2m0ar = crate::Reg<s2m0ar::S2m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s2m0ar;
#[doc = "S2M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s2m1ar`]
module"]
#[doc(alias = "S2M1AR")]
pub type S2m1ar = crate::Reg<s2m1ar::S2m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s2m1ar;
#[doc = "S2FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s2fcr`]
module"]
#[doc(alias = "S2FCR")]
pub type S2fcr = crate::Reg<s2fcr::S2fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s2fcr;
#[doc = "S3CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s3cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s3cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s3cr`]
module"]
#[doc(alias = "S3CR")]
pub type S3cr = crate::Reg<s3cr::S3crSpec>;
#[doc = "stream x configuration register"]
pub mod s3cr;
#[doc = "S3NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s3ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s3ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s3ndtr`]
module"]
#[doc(alias = "S3NDTR")]
pub type S3ndtr = crate::Reg<s3ndtr::S3ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s3ndtr;
#[doc = "S3PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s3par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s3par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s3par`]
module"]
#[doc(alias = "S3PAR")]
pub type S3par = crate::Reg<s3par::S3parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s3par;
#[doc = "S3M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s3m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s3m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s3m0ar`]
module"]
#[doc(alias = "S3M0AR")]
pub type S3m0ar = crate::Reg<s3m0ar::S3m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s3m0ar;
#[doc = "S3M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s3m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s3m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s3m1ar`]
module"]
#[doc(alias = "S3M1AR")]
pub type S3m1ar = crate::Reg<s3m1ar::S3m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s3m1ar;
#[doc = "S3FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s3fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s3fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s3fcr`]
module"]
#[doc(alias = "S3FCR")]
pub type S3fcr = crate::Reg<s3fcr::S3fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s3fcr;
#[doc = "S4CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s4cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s4cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s4cr`]
module"]
#[doc(alias = "S4CR")]
pub type S4cr = crate::Reg<s4cr::S4crSpec>;
#[doc = "stream x configuration register"]
pub mod s4cr;
#[doc = "S4NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s4ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s4ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s4ndtr`]
module"]
#[doc(alias = "S4NDTR")]
pub type S4ndtr = crate::Reg<s4ndtr::S4ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s4ndtr;
#[doc = "S4PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s4par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s4par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s4par`]
module"]
#[doc(alias = "S4PAR")]
pub type S4par = crate::Reg<s4par::S4parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s4par;
#[doc = "S4M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s4m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s4m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s4m0ar`]
module"]
#[doc(alias = "S4M0AR")]
pub type S4m0ar = crate::Reg<s4m0ar::S4m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s4m0ar;
#[doc = "S4M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s4m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s4m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s4m1ar`]
module"]
#[doc(alias = "S4M1AR")]
pub type S4m1ar = crate::Reg<s4m1ar::S4m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s4m1ar;
#[doc = "S4FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s4fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s4fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s4fcr`]
module"]
#[doc(alias = "S4FCR")]
pub type S4fcr = crate::Reg<s4fcr::S4fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s4fcr;
#[doc = "S5CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s5cr`]
module"]
#[doc(alias = "S5CR")]
pub type S5cr = crate::Reg<s5cr::S5crSpec>;
#[doc = "stream x configuration register"]
pub mod s5cr;
#[doc = "S5NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s5ndtr`]
module"]
#[doc(alias = "S5NDTR")]
pub type S5ndtr = crate::Reg<s5ndtr::S5ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s5ndtr;
#[doc = "S5PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s5par`]
module"]
#[doc(alias = "S5PAR")]
pub type S5par = crate::Reg<s5par::S5parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s5par;
#[doc = "S5M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s5m0ar`]
module"]
#[doc(alias = "S5M0AR")]
pub type S5m0ar = crate::Reg<s5m0ar::S5m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s5m0ar;
#[doc = "S5M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s5m1ar`]
module"]
#[doc(alias = "S5M1AR")]
pub type S5m1ar = crate::Reg<s5m1ar::S5m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s5m1ar;
#[doc = "S5FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s5fcr`]
module"]
#[doc(alias = "S5FCR")]
pub type S5fcr = crate::Reg<s5fcr::S5fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s5fcr;
#[doc = "S6CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s6cr`]
module"]
#[doc(alias = "S6CR")]
pub type S6cr = crate::Reg<s6cr::S6crSpec>;
#[doc = "stream x configuration register"]
pub mod s6cr;
#[doc = "S6NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s6ndtr`]
module"]
#[doc(alias = "S6NDTR")]
pub type S6ndtr = crate::Reg<s6ndtr::S6ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s6ndtr;
#[doc = "S6PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s6par`]
module"]
#[doc(alias = "S6PAR")]
pub type S6par = crate::Reg<s6par::S6parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s6par;
#[doc = "S6M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s6m0ar`]
module"]
#[doc(alias = "S6M0AR")]
pub type S6m0ar = crate::Reg<s6m0ar::S6m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s6m0ar;
#[doc = "S6M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s6m1ar`]
module"]
#[doc(alias = "S6M1AR")]
pub type S6m1ar = crate::Reg<s6m1ar::S6m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s6m1ar;
#[doc = "S6FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s6fcr`]
module"]
#[doc(alias = "S6FCR")]
pub type S6fcr = crate::Reg<s6fcr::S6fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s6fcr;
#[doc = "S7CR (rw) register accessor: stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s7cr`]
module"]
#[doc(alias = "S7CR")]
pub type S7cr = crate::Reg<s7cr::S7crSpec>;
#[doc = "stream x configuration register"]
pub mod s7cr;
#[doc = "S7NDTR (rw) register accessor: stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7ndtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7ndtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s7ndtr`]
module"]
#[doc(alias = "S7NDTR")]
pub type S7ndtr = crate::Reg<s7ndtr::S7ndtrSpec>;
#[doc = "stream x number of data register"]
pub mod s7ndtr;
#[doc = "S7PAR (rw) register accessor: stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7par::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7par::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s7par`]
module"]
#[doc(alias = "S7PAR")]
pub type S7par = crate::Reg<s7par::S7parSpec>;
#[doc = "stream x peripheral address register"]
pub mod s7par;
#[doc = "S7M0AR (rw) register accessor: stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7m0ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7m0ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s7m0ar`]
module"]
#[doc(alias = "S7M0AR")]
pub type S7m0ar = crate::Reg<s7m0ar::S7m0arSpec>;
#[doc = "stream x memory 0 address register"]
pub mod s7m0ar;
#[doc = "S7M1AR (rw) register accessor: stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7m1ar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7m1ar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s7m1ar`]
module"]
#[doc(alias = "S7M1AR")]
pub type S7m1ar = crate::Reg<s7m1ar::S7m1arSpec>;
#[doc = "stream x memory 1 address register"]
pub mod s7m1ar;
#[doc = "S7FCR (rw) register accessor: stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7fcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7fcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@s7fcr`]
module"]
#[doc(alias = "S7FCR")]
pub type S7fcr = crate::Reg<s7fcr::S7fcrSpec>;
#[doc = "stream x FIFO control register"]
pub mod s7fcr;
