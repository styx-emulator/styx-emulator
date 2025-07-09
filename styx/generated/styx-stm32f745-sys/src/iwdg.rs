// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    kr: Kr,
    pr: Pr,
    rlr: Rlr,
    sr: Sr,
    winr: Winr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Key register"]
    #[inline(always)]
    pub const fn kr(&self) -> &Kr {
        &self.kr
    }
    #[doc = "0x04 - Prescaler register"]
    #[inline(always)]
    pub const fn pr(&self) -> &Pr {
        &self.pr
    }
    #[doc = "0x08 - Reload register"]
    #[inline(always)]
    pub const fn rlr(&self) -> &Rlr {
        &self.rlr
    }
    #[doc = "0x0c - Status register"]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0x10 - Window register"]
    #[inline(always)]
    pub const fn winr(&self) -> &Winr {
        &self.winr
    }
}
#[doc = "KR (w) register accessor: Key register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`kr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@kr`]
module"]
#[doc(alias = "KR")]
pub type Kr = crate::Reg<kr::KrSpec>;
#[doc = "Key register"]
pub mod kr;
#[doc = "PR (rw) register accessor: Prescaler register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pr`]
module"]
#[doc(alias = "PR")]
pub type Pr = crate::Reg<pr::PrSpec>;
#[doc = "Prescaler register"]
pub mod pr;
#[doc = "RLR (rw) register accessor: Reload register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rlr`]
module"]
#[doc(alias = "RLR")]
pub type Rlr = crate::Reg<rlr::RlrSpec>;
#[doc = "Reload register"]
pub mod rlr;
#[doc = "SR (r) register accessor: Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "SR")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "Status register"]
pub mod sr;
#[doc = "WINR (rw) register accessor: Window register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`winr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`winr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@winr`]
module"]
#[doc(alias = "WINR")]
pub type Winr = crate::Reg<winr::WinrSpec>;
#[doc = "Window register"]
pub mod winr;
