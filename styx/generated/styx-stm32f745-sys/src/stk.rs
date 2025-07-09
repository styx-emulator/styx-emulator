// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    csr: Csr,
    rvr: Rvr,
    cvr: Cvr,
    calib: Calib,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - SysTick control and status register"]
    #[inline(always)]
    pub const fn csr(&self) -> &Csr {
        &self.csr
    }
    #[doc = "0x04 - SysTick reload value register"]
    #[inline(always)]
    pub const fn rvr(&self) -> &Rvr {
        &self.rvr
    }
    #[doc = "0x08 - SysTick current value register"]
    #[inline(always)]
    pub const fn cvr(&self) -> &Cvr {
        &self.cvr
    }
    #[doc = "0x0c - SysTick calibration value register"]
    #[inline(always)]
    pub const fn calib(&self) -> &Calib {
        &self.calib
    }
}
#[doc = "CSR (rw) register accessor: SysTick control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr`]
module"]
#[doc(alias = "CSR")]
pub type Csr = crate::Reg<csr::CsrSpec>;
#[doc = "SysTick control and status register"]
pub mod csr;
#[doc = "RVR (rw) register accessor: SysTick reload value register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rvr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rvr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rvr`]
module"]
#[doc(alias = "RVR")]
pub type Rvr = crate::Reg<rvr::RvrSpec>;
#[doc = "SysTick reload value register"]
pub mod rvr;
#[doc = "CVR (rw) register accessor: SysTick current value register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cvr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cvr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cvr`]
module"]
#[doc(alias = "CVR")]
pub type Cvr = crate::Reg<cvr::CvrSpec>;
#[doc = "SysTick current value register"]
pub mod cvr;
#[doc = "CALIB (rw) register accessor: SysTick calibration value register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`calib::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`calib::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@calib`]
module"]
#[doc(alias = "CALIB")]
pub type Calib = crate::Reg<calib::CalibSpec>;
#[doc = "SysTick calibration value register"]
pub mod calib;
