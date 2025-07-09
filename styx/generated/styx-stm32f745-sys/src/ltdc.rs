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
    _reserved0: [u8; 0x08],
    sscr: Sscr,
    bpcr: Bpcr,
    awcr: Awcr,
    twcr: Twcr,
    gcr: Gcr,
    _reserved5: [u8; 0x08],
    srcr: Srcr,
    _reserved6: [u8; 0x04],
    bccr: Bccr,
    _reserved7: [u8; 0x04],
    ier: Ier,
    isr: Isr,
    icr: Icr,
    lipcr: Lipcr,
    cpsr: Cpsr,
    cdsr: Cdsr,
    _reserved13: [u8; 0x38],
    l1cr: L1cr,
    l1whpcr: L1whpcr,
    l1wvpcr: L1wvpcr,
    l1ckcr: L1ckcr,
    l1pfcr: L1pfcr,
    l1cacr: L1cacr,
    l1dccr: L1dccr,
    l1bfcr: L1bfcr,
    _reserved21: [u8; 0x08],
    l1cfbar: L1cfbar,
    l1cfblr: L1cfblr,
    l1cfblnr: L1cfblnr,
    _reserved24: [u8; 0x0c],
    l1clutwr: L1clutwr,
    _reserved25: [u8; 0x3c],
    l2cr: L2cr,
    l2whpcr: L2whpcr,
    l2wvpcr: L2wvpcr,
    l2ckcr: L2ckcr,
    l2pfcr: L2pfcr,
    l2cacr: L2cacr,
    l2dccr: L2dccr,
    l2bfcr: L2bfcr,
    _reserved33: [u8; 0x08],
    l2cfbar: L2cfbar,
    l2cfblr: L2cfblr,
    l2cfblnr: L2cfblnr,
    _reserved36: [u8; 0x0c],
    l2clutwr: L2clutwr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x08 - Synchronization Size Configuration Register"]
    #[inline(always)]
    pub const fn sscr(&self) -> &Sscr {
        &self.sscr
    }
    #[doc = "0x0c - Back Porch Configuration Register"]
    #[inline(always)]
    pub const fn bpcr(&self) -> &Bpcr {
        &self.bpcr
    }
    #[doc = "0x10 - Active Width Configuration Register"]
    #[inline(always)]
    pub const fn awcr(&self) -> &Awcr {
        &self.awcr
    }
    #[doc = "0x14 - Total Width Configuration Register"]
    #[inline(always)]
    pub const fn twcr(&self) -> &Twcr {
        &self.twcr
    }
    #[doc = "0x18 - Global Control Register"]
    #[inline(always)]
    pub const fn gcr(&self) -> &Gcr {
        &self.gcr
    }
    #[doc = "0x24 - Shadow Reload Configuration Register"]
    #[inline(always)]
    pub const fn srcr(&self) -> &Srcr {
        &self.srcr
    }
    #[doc = "0x2c - Background Color Configuration Register"]
    #[inline(always)]
    pub const fn bccr(&self) -> &Bccr {
        &self.bccr
    }
    #[doc = "0x34 - Interrupt Enable Register"]
    #[inline(always)]
    pub const fn ier(&self) -> &Ier {
        &self.ier
    }
    #[doc = "0x38 - Interrupt Status Register"]
    #[inline(always)]
    pub const fn isr(&self) -> &Isr {
        &self.isr
    }
    #[doc = "0x3c - Interrupt Clear Register"]
    #[inline(always)]
    pub const fn icr(&self) -> &Icr {
        &self.icr
    }
    #[doc = "0x40 - Line Interrupt Position Configuration Register"]
    #[inline(always)]
    pub const fn lipcr(&self) -> &Lipcr {
        &self.lipcr
    }
    #[doc = "0x44 - Current Position Status Register"]
    #[inline(always)]
    pub const fn cpsr(&self) -> &Cpsr {
        &self.cpsr
    }
    #[doc = "0x48 - Current Display Status Register"]
    #[inline(always)]
    pub const fn cdsr(&self) -> &Cdsr {
        &self.cdsr
    }
    #[doc = "0x84 - Layerx Control Register"]
    #[inline(always)]
    pub const fn l1cr(&self) -> &L1cr {
        &self.l1cr
    }
    #[doc = "0x88 - Layerx Window Horizontal Position Configuration Register"]
    #[inline(always)]
    pub const fn l1whpcr(&self) -> &L1whpcr {
        &self.l1whpcr
    }
    #[doc = "0x8c - Layerx Window Vertical Position Configuration Register"]
    #[inline(always)]
    pub const fn l1wvpcr(&self) -> &L1wvpcr {
        &self.l1wvpcr
    }
    #[doc = "0x90 - Layerx Color Keying Configuration Register"]
    #[inline(always)]
    pub const fn l1ckcr(&self) -> &L1ckcr {
        &self.l1ckcr
    }
    #[doc = "0x94 - Layerx Pixel Format Configuration Register"]
    #[inline(always)]
    pub const fn l1pfcr(&self) -> &L1pfcr {
        &self.l1pfcr
    }
    #[doc = "0x98 - Layerx Constant Alpha Configuration Register"]
    #[inline(always)]
    pub const fn l1cacr(&self) -> &L1cacr {
        &self.l1cacr
    }
    #[doc = "0x9c - Layerx Default Color Configuration Register"]
    #[inline(always)]
    pub const fn l1dccr(&self) -> &L1dccr {
        &self.l1dccr
    }
    #[doc = "0xa0 - Layerx Blending Factors Configuration Register"]
    #[inline(always)]
    pub const fn l1bfcr(&self) -> &L1bfcr {
        &self.l1bfcr
    }
    #[doc = "0xac - Layerx Color Frame Buffer Address Register"]
    #[inline(always)]
    pub const fn l1cfbar(&self) -> &L1cfbar {
        &self.l1cfbar
    }
    #[doc = "0xb0 - Layerx Color Frame Buffer Length Register"]
    #[inline(always)]
    pub const fn l1cfblr(&self) -> &L1cfblr {
        &self.l1cfblr
    }
    #[doc = "0xb4 - Layerx ColorFrame Buffer Line Number Register"]
    #[inline(always)]
    pub const fn l1cfblnr(&self) -> &L1cfblnr {
        &self.l1cfblnr
    }
    #[doc = "0xc4 - Layerx CLUT Write Register"]
    #[inline(always)]
    pub const fn l1clutwr(&self) -> &L1clutwr {
        &self.l1clutwr
    }
    #[doc = "0x104 - Layerx Control Register"]
    #[inline(always)]
    pub const fn l2cr(&self) -> &L2cr {
        &self.l2cr
    }
    #[doc = "0x108 - Layerx Window Horizontal Position Configuration Register"]
    #[inline(always)]
    pub const fn l2whpcr(&self) -> &L2whpcr {
        &self.l2whpcr
    }
    #[doc = "0x10c - Layerx Window Vertical Position Configuration Register"]
    #[inline(always)]
    pub const fn l2wvpcr(&self) -> &L2wvpcr {
        &self.l2wvpcr
    }
    #[doc = "0x110 - Layerx Color Keying Configuration Register"]
    #[inline(always)]
    pub const fn l2ckcr(&self) -> &L2ckcr {
        &self.l2ckcr
    }
    #[doc = "0x114 - Layerx Pixel Format Configuration Register"]
    #[inline(always)]
    pub const fn l2pfcr(&self) -> &L2pfcr {
        &self.l2pfcr
    }
    #[doc = "0x118 - Layerx Constant Alpha Configuration Register"]
    #[inline(always)]
    pub const fn l2cacr(&self) -> &L2cacr {
        &self.l2cacr
    }
    #[doc = "0x11c - Layerx Default Color Configuration Register"]
    #[inline(always)]
    pub const fn l2dccr(&self) -> &L2dccr {
        &self.l2dccr
    }
    #[doc = "0x120 - Layerx Blending Factors Configuration Register"]
    #[inline(always)]
    pub const fn l2bfcr(&self) -> &L2bfcr {
        &self.l2bfcr
    }
    #[doc = "0x12c - Layerx Color Frame Buffer Address Register"]
    #[inline(always)]
    pub const fn l2cfbar(&self) -> &L2cfbar {
        &self.l2cfbar
    }
    #[doc = "0x130 - Layerx Color Frame Buffer Length Register"]
    #[inline(always)]
    pub const fn l2cfblr(&self) -> &L2cfblr {
        &self.l2cfblr
    }
    #[doc = "0x134 - Layerx ColorFrame Buffer Line Number Register"]
    #[inline(always)]
    pub const fn l2cfblnr(&self) -> &L2cfblnr {
        &self.l2cfblnr
    }
    #[doc = "0x144 - Layerx CLUT Write Register"]
    #[inline(always)]
    pub const fn l2clutwr(&self) -> &L2clutwr {
        &self.l2clutwr
    }
}
#[doc = "SSCR (rw) register accessor: Synchronization Size Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sscr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sscr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sscr`]
module"]
#[doc(alias = "SSCR")]
pub type Sscr = crate::Reg<sscr::SscrSpec>;
#[doc = "Synchronization Size Configuration Register"]
pub mod sscr;
#[doc = "BPCR (rw) register accessor: Back Porch Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bpcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bpcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bpcr`]
module"]
#[doc(alias = "BPCR")]
pub type Bpcr = crate::Reg<bpcr::BpcrSpec>;
#[doc = "Back Porch Configuration Register"]
pub mod bpcr;
#[doc = "AWCR (rw) register accessor: Active Width Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`awcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`awcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@awcr`]
module"]
#[doc(alias = "AWCR")]
pub type Awcr = crate::Reg<awcr::AwcrSpec>;
#[doc = "Active Width Configuration Register"]
pub mod awcr;
#[doc = "TWCR (rw) register accessor: Total Width Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`twcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`twcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@twcr`]
module"]
#[doc(alias = "TWCR")]
pub type Twcr = crate::Reg<twcr::TwcrSpec>;
#[doc = "Total Width Configuration Register"]
pub mod twcr;
#[doc = "GCR (rw) register accessor: Global Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gcr`]
module"]
#[doc(alias = "GCR")]
pub type Gcr = crate::Reg<gcr::GcrSpec>;
#[doc = "Global Control Register"]
pub mod gcr;
#[doc = "SRCR (rw) register accessor: Shadow Reload Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@srcr`]
module"]
#[doc(alias = "SRCR")]
pub type Srcr = crate::Reg<srcr::SrcrSpec>;
#[doc = "Shadow Reload Configuration Register"]
pub mod srcr;
#[doc = "BCCR (rw) register accessor: Background Color Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bccr`]
module"]
#[doc(alias = "BCCR")]
pub type Bccr = crate::Reg<bccr::BccrSpec>;
#[doc = "Background Color Configuration Register"]
pub mod bccr;
#[doc = "IER (rw) register accessor: Interrupt Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ier::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ier::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ier`]
module"]
#[doc(alias = "IER")]
pub type Ier = crate::Reg<ier::IerSpec>;
#[doc = "Interrupt Enable Register"]
pub mod ier;
#[doc = "ISR (r) register accessor: Interrupt Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@isr`]
module"]
#[doc(alias = "ISR")]
pub type Isr = crate::Reg<isr::IsrSpec>;
#[doc = "Interrupt Status Register"]
pub mod isr;
#[doc = "ICR (w) register accessor: Interrupt Clear Register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icr`]
module"]
#[doc(alias = "ICR")]
pub type Icr = crate::Reg<icr::IcrSpec>;
#[doc = "Interrupt Clear Register"]
pub mod icr;
#[doc = "LIPCR (rw) register accessor: Line Interrupt Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lipcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lipcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lipcr`]
module"]
#[doc(alias = "LIPCR")]
pub type Lipcr = crate::Reg<lipcr::LipcrSpec>;
#[doc = "Line Interrupt Position Configuration Register"]
pub mod lipcr;
#[doc = "CPSR (r) register accessor: Current Position Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cpsr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cpsr`]
module"]
#[doc(alias = "CPSR")]
pub type Cpsr = crate::Reg<cpsr::CpsrSpec>;
#[doc = "Current Position Status Register"]
pub mod cpsr;
#[doc = "CDSR (r) register accessor: Current Display Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cdsr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cdsr`]
module"]
#[doc(alias = "CDSR")]
pub type Cdsr = crate::Reg<cdsr::CdsrSpec>;
#[doc = "Current Display Status Register"]
pub mod cdsr;
#[doc = "L1CR (rw) register accessor: Layerx Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1cr`]
module"]
#[doc(alias = "L1CR")]
pub type L1cr = crate::Reg<l1cr::L1crSpec>;
#[doc = "Layerx Control Register"]
pub mod l1cr;
#[doc = "L1WHPCR (rw) register accessor: Layerx Window Horizontal Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1whpcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1whpcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1whpcr`]
module"]
#[doc(alias = "L1WHPCR")]
pub type L1whpcr = crate::Reg<l1whpcr::L1whpcrSpec>;
#[doc = "Layerx Window Horizontal Position Configuration Register"]
pub mod l1whpcr;
#[doc = "L1WVPCR (rw) register accessor: Layerx Window Vertical Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1wvpcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1wvpcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1wvpcr`]
module"]
#[doc(alias = "L1WVPCR")]
pub type L1wvpcr = crate::Reg<l1wvpcr::L1wvpcrSpec>;
#[doc = "Layerx Window Vertical Position Configuration Register"]
pub mod l1wvpcr;
#[doc = "L1CKCR (rw) register accessor: Layerx Color Keying Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1ckcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1ckcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1ckcr`]
module"]
#[doc(alias = "L1CKCR")]
pub type L1ckcr = crate::Reg<l1ckcr::L1ckcrSpec>;
#[doc = "Layerx Color Keying Configuration Register"]
pub mod l1ckcr;
#[doc = "L1PFCR (rw) register accessor: Layerx Pixel Format Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1pfcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1pfcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1pfcr`]
module"]
#[doc(alias = "L1PFCR")]
pub type L1pfcr = crate::Reg<l1pfcr::L1pfcrSpec>;
#[doc = "Layerx Pixel Format Configuration Register"]
pub mod l1pfcr;
#[doc = "L1CACR (rw) register accessor: Layerx Constant Alpha Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cacr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cacr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1cacr`]
module"]
#[doc(alias = "L1CACR")]
pub type L1cacr = crate::Reg<l1cacr::L1cacrSpec>;
#[doc = "Layerx Constant Alpha Configuration Register"]
pub mod l1cacr;
#[doc = "L1DCCR (rw) register accessor: Layerx Default Color Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1dccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1dccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1dccr`]
module"]
#[doc(alias = "L1DCCR")]
pub type L1dccr = crate::Reg<l1dccr::L1dccrSpec>;
#[doc = "Layerx Default Color Configuration Register"]
pub mod l1dccr;
#[doc = "L1BFCR (rw) register accessor: Layerx Blending Factors Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1bfcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1bfcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1bfcr`]
module"]
#[doc(alias = "L1BFCR")]
pub type L1bfcr = crate::Reg<l1bfcr::L1bfcrSpec>;
#[doc = "Layerx Blending Factors Configuration Register"]
pub mod l1bfcr;
#[doc = "L1CFBAR (rw) register accessor: Layerx Color Frame Buffer Address Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cfbar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cfbar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1cfbar`]
module"]
#[doc(alias = "L1CFBAR")]
pub type L1cfbar = crate::Reg<l1cfbar::L1cfbarSpec>;
#[doc = "Layerx Color Frame Buffer Address Register"]
pub mod l1cfbar;
#[doc = "L1CFBLR (rw) register accessor: Layerx Color Frame Buffer Length Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cfblr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cfblr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1cfblr`]
module"]
#[doc(alias = "L1CFBLR")]
pub type L1cfblr = crate::Reg<l1cfblr::L1cfblrSpec>;
#[doc = "Layerx Color Frame Buffer Length Register"]
pub mod l1cfblr;
#[doc = "L1CFBLNR (rw) register accessor: Layerx ColorFrame Buffer Line Number Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cfblnr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cfblnr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1cfblnr`]
module"]
#[doc(alias = "L1CFBLNR")]
pub type L1cfblnr = crate::Reg<l1cfblnr::L1cfblnrSpec>;
#[doc = "Layerx ColorFrame Buffer Line Number Register"]
pub mod l1cfblnr;
#[doc = "L1CLUTWR (w) register accessor: Layerx CLUT Write Register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1clutwr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l1clutwr`]
module"]
#[doc(alias = "L1CLUTWR")]
pub type L1clutwr = crate::Reg<l1clutwr::L1clutwrSpec>;
#[doc = "Layerx CLUT Write Register"]
pub mod l1clutwr;
#[doc = "L2CR (rw) register accessor: Layerx Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2cr`]
module"]
#[doc(alias = "L2CR")]
pub type L2cr = crate::Reg<l2cr::L2crSpec>;
#[doc = "Layerx Control Register"]
pub mod l2cr;
#[doc = "L2WHPCR (rw) register accessor: Layerx Window Horizontal Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2whpcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2whpcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2whpcr`]
module"]
#[doc(alias = "L2WHPCR")]
pub type L2whpcr = crate::Reg<l2whpcr::L2whpcrSpec>;
#[doc = "Layerx Window Horizontal Position Configuration Register"]
pub mod l2whpcr;
#[doc = "L2WVPCR (rw) register accessor: Layerx Window Vertical Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2wvpcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2wvpcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2wvpcr`]
module"]
#[doc(alias = "L2WVPCR")]
pub type L2wvpcr = crate::Reg<l2wvpcr::L2wvpcrSpec>;
#[doc = "Layerx Window Vertical Position Configuration Register"]
pub mod l2wvpcr;
#[doc = "L2CKCR (rw) register accessor: Layerx Color Keying Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2ckcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2ckcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2ckcr`]
module"]
#[doc(alias = "L2CKCR")]
pub type L2ckcr = crate::Reg<l2ckcr::L2ckcrSpec>;
#[doc = "Layerx Color Keying Configuration Register"]
pub mod l2ckcr;
#[doc = "L2PFCR (rw) register accessor: Layerx Pixel Format Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2pfcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2pfcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2pfcr`]
module"]
#[doc(alias = "L2PFCR")]
pub type L2pfcr = crate::Reg<l2pfcr::L2pfcrSpec>;
#[doc = "Layerx Pixel Format Configuration Register"]
pub mod l2pfcr;
#[doc = "L2CACR (rw) register accessor: Layerx Constant Alpha Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2cacr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2cacr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2cacr`]
module"]
#[doc(alias = "L2CACR")]
pub type L2cacr = crate::Reg<l2cacr::L2cacrSpec>;
#[doc = "Layerx Constant Alpha Configuration Register"]
pub mod l2cacr;
#[doc = "L2DCCR (rw) register accessor: Layerx Default Color Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2dccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2dccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2dccr`]
module"]
#[doc(alias = "L2DCCR")]
pub type L2dccr = crate::Reg<l2dccr::L2dccrSpec>;
#[doc = "Layerx Default Color Configuration Register"]
pub mod l2dccr;
#[doc = "L2BFCR (rw) register accessor: Layerx Blending Factors Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2bfcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2bfcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2bfcr`]
module"]
#[doc(alias = "L2BFCR")]
pub type L2bfcr = crate::Reg<l2bfcr::L2bfcrSpec>;
#[doc = "Layerx Blending Factors Configuration Register"]
pub mod l2bfcr;
#[doc = "L2CFBAR (rw) register accessor: Layerx Color Frame Buffer Address Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2cfbar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2cfbar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2cfbar`]
module"]
#[doc(alias = "L2CFBAR")]
pub type L2cfbar = crate::Reg<l2cfbar::L2cfbarSpec>;
#[doc = "Layerx Color Frame Buffer Address Register"]
pub mod l2cfbar;
#[doc = "L2CFBLR (rw) register accessor: Layerx Color Frame Buffer Length Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2cfblr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2cfblr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2cfblr`]
module"]
#[doc(alias = "L2CFBLR")]
pub type L2cfblr = crate::Reg<l2cfblr::L2cfblrSpec>;
#[doc = "Layerx Color Frame Buffer Length Register"]
pub mod l2cfblr;
#[doc = "L2CFBLNR (rw) register accessor: Layerx ColorFrame Buffer Line Number Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2cfblnr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2cfblnr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2cfblnr`]
module"]
#[doc(alias = "L2CFBLNR")]
pub type L2cfblnr = crate::Reg<l2cfblnr::L2cfblnrSpec>;
#[doc = "Layerx ColorFrame Buffer Line Number Register"]
pub mod l2cfblnr;
#[doc = "L2CLUTWR (w) register accessor: Layerx CLUT Write Register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2clutwr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@l2clutwr`]
module"]
#[doc(alias = "L2CLUTWR")]
pub type L2clutwr = crate::Reg<l2clutwr::L2clutwrSpec>;
#[doc = "Layerx CLUT Write Register"]
pub mod l2clutwr;
