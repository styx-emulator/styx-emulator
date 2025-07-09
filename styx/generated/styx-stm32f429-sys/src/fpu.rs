// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    fpccr: Fpccr,
    fpcar: Fpcar,
    fpscr: Fpscr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Floating-point context control register"]
    #[inline(always)]
    pub const fn fpccr(&self) -> &Fpccr {
        &self.fpccr
    }
    #[doc = "0x04 - Floating-point context address register"]
    #[inline(always)]
    pub const fn fpcar(&self) -> &Fpcar {
        &self.fpcar
    }
    #[doc = "0x08 - Floating-point status control register"]
    #[inline(always)]
    pub const fn fpscr(&self) -> &Fpscr {
        &self.fpscr
    }
}
#[doc = "FPCCR (rw) register accessor: Floating-point context control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fpccr`]
module"]
#[doc(alias = "FPCCR")]
pub type Fpccr = crate::Reg<fpccr::FpccrSpec>;
#[doc = "Floating-point context control register"]
pub mod fpccr;
#[doc = "FPCAR (rw) register accessor: Floating-point context address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpcar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpcar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fpcar`]
module"]
#[doc(alias = "FPCAR")]
pub type Fpcar = crate::Reg<fpcar::FpcarSpec>;
#[doc = "Floating-point context address register"]
pub mod fpcar;
#[doc = "FPSCR (rw) register accessor: Floating-point status control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpscr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpscr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fpscr`]
module"]
#[doc(alias = "FPSCR")]
pub type Fpscr = crate::Reg<fpscr::FpscrSpec>;
#[doc = "Floating-point status control register"]
pub mod fpscr;
