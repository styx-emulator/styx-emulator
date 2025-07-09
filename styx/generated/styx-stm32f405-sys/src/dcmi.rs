// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    cr: Cr,
    sr: Sr,
    ris: Ris,
    ier: Ier,
    mis: Mis,
    icr: Icr,
    escr: Escr,
    esur: Esur,
    cwstrt: Cwstrt,
    cwsize: Cwsize,
    dr: Dr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - control register 1"]
    #[inline(always)]
    pub const fn cr(&self) -> &Cr {
        &self.cr
    }
    #[doc = "0x04 - status register"]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0x08 - raw interrupt status register"]
    #[inline(always)]
    pub const fn ris(&self) -> &Ris {
        &self.ris
    }
    #[doc = "0x0c - interrupt enable register"]
    #[inline(always)]
    pub const fn ier(&self) -> &Ier {
        &self.ier
    }
    #[doc = "0x10 - masked interrupt status register"]
    #[inline(always)]
    pub const fn mis(&self) -> &Mis {
        &self.mis
    }
    #[doc = "0x14 - interrupt clear register"]
    #[inline(always)]
    pub const fn icr(&self) -> &Icr {
        &self.icr
    }
    #[doc = "0x18 - embedded synchronization code register"]
    #[inline(always)]
    pub const fn escr(&self) -> &Escr {
        &self.escr
    }
    #[doc = "0x1c - embedded synchronization unmask register"]
    #[inline(always)]
    pub const fn esur(&self) -> &Esur {
        &self.esur
    }
    #[doc = "0x20 - crop window start"]
    #[inline(always)]
    pub const fn cwstrt(&self) -> &Cwstrt {
        &self.cwstrt
    }
    #[doc = "0x24 - crop window size"]
    #[inline(always)]
    pub const fn cwsize(&self) -> &Cwsize {
        &self.cwsize
    }
    #[doc = "0x28 - data register"]
    #[inline(always)]
    pub const fn dr(&self) -> &Dr {
        &self.dr
    }
}
#[doc = "CR (rw) register accessor: control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr`]
module"]
#[doc(alias = "CR")]
pub type Cr = crate::Reg<cr::CrSpec>;
#[doc = "control register 1"]
pub mod cr;
#[doc = "SR (r) register accessor: status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "SR")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "status register"]
pub mod sr;
#[doc = "RIS (r) register accessor: raw interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ris::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ris`]
module"]
#[doc(alias = "RIS")]
pub type Ris = crate::Reg<ris::RisSpec>;
#[doc = "raw interrupt status register"]
pub mod ris;
#[doc = "IER (rw) register accessor: interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ier::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ier::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ier`]
module"]
#[doc(alias = "IER")]
pub type Ier = crate::Reg<ier::IerSpec>;
#[doc = "interrupt enable register"]
pub mod ier;
#[doc = "MIS (r) register accessor: masked interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mis::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mis`]
module"]
#[doc(alias = "MIS")]
pub type Mis = crate::Reg<mis::MisSpec>;
#[doc = "masked interrupt status register"]
pub mod mis;
#[doc = "ICR (w) register accessor: interrupt clear register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icr`]
module"]
#[doc(alias = "ICR")]
pub type Icr = crate::Reg<icr::IcrSpec>;
#[doc = "interrupt clear register"]
pub mod icr;
#[doc = "ESCR (rw) register accessor: embedded synchronization code register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`escr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`escr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@escr`]
module"]
#[doc(alias = "ESCR")]
pub type Escr = crate::Reg<escr::EscrSpec>;
#[doc = "embedded synchronization code register"]
pub mod escr;
#[doc = "ESUR (rw) register accessor: embedded synchronization unmask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`esur::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`esur::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@esur`]
module"]
#[doc(alias = "ESUR")]
pub type Esur = crate::Reg<esur::EsurSpec>;
#[doc = "embedded synchronization unmask register"]
pub mod esur;
#[doc = "CWSTRT (rw) register accessor: crop window start\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cwstrt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cwstrt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cwstrt`]
module"]
#[doc(alias = "CWSTRT")]
pub type Cwstrt = crate::Reg<cwstrt::CwstrtSpec>;
#[doc = "crop window start"]
pub mod cwstrt;
#[doc = "CWSIZE (rw) register accessor: crop window size\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cwsize::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cwsize::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cwsize`]
module"]
#[doc(alias = "CWSIZE")]
pub type Cwsize = crate::Reg<cwsize::CwsizeSpec>;
#[doc = "crop window size"]
pub mod cwsize;
#[doc = "DR (r) register accessor: data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dr`]
module"]
#[doc(alias = "DR")]
pub type Dr = crate::Reg<dr::DrSpec>;
#[doc = "data register"]
pub mod dr;
