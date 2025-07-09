// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    imr: Imr,
    emr: Emr,
    rtsr: Rtsr,
    ftsr: Ftsr,
    swier: Swier,
    pr: Pr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Interrupt mask register (EXTI_IMR)"]
    #[inline(always)]
    pub const fn imr(&self) -> &Imr {
        &self.imr
    }
    #[doc = "0x04 - Event mask register (EXTI_EMR)"]
    #[inline(always)]
    pub const fn emr(&self) -> &Emr {
        &self.emr
    }
    #[doc = "0x08 - Rising Trigger selection register (EXTI_RTSR)"]
    #[inline(always)]
    pub const fn rtsr(&self) -> &Rtsr {
        &self.rtsr
    }
    #[doc = "0x0c - Falling Trigger selection register (EXTI_FTSR)"]
    #[inline(always)]
    pub const fn ftsr(&self) -> &Ftsr {
        &self.ftsr
    }
    #[doc = "0x10 - Software interrupt event register (EXTI_SWIER)"]
    #[inline(always)]
    pub const fn swier(&self) -> &Swier {
        &self.swier
    }
    #[doc = "0x14 - Pending register (EXTI_PR)"]
    #[inline(always)]
    pub const fn pr(&self) -> &Pr {
        &self.pr
    }
}
#[doc = "IMR (rw) register accessor: Interrupt mask register (EXTI_IMR)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`imr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`imr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@imr`]
module"]
#[doc(alias = "IMR")]
pub type Imr = crate::Reg<imr::ImrSpec>;
#[doc = "Interrupt mask register (EXTI_IMR)"]
pub mod imr;
#[doc = "EMR (rw) register accessor: Event mask register (EXTI_EMR)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`emr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`emr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@emr`]
module"]
#[doc(alias = "EMR")]
pub type Emr = crate::Reg<emr::EmrSpec>;
#[doc = "Event mask register (EXTI_EMR)"]
pub mod emr;
#[doc = "RTSR (rw) register accessor: Rising Trigger selection register (EXTI_RTSR)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rtsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rtsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rtsr`]
module"]
#[doc(alias = "RTSR")]
pub type Rtsr = crate::Reg<rtsr::RtsrSpec>;
#[doc = "Rising Trigger selection register (EXTI_RTSR)"]
pub mod rtsr;
#[doc = "FTSR (rw) register accessor: Falling Trigger selection register (EXTI_FTSR)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ftsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ftsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ftsr`]
module"]
#[doc(alias = "FTSR")]
pub type Ftsr = crate::Reg<ftsr::FtsrSpec>;
#[doc = "Falling Trigger selection register (EXTI_FTSR)"]
pub mod ftsr;
#[doc = "SWIER (rw) register accessor: Software interrupt event register (EXTI_SWIER)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`swier::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`swier::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@swier`]
module"]
#[doc(alias = "SWIER")]
pub type Swier = crate::Reg<swier::SwierSpec>;
#[doc = "Software interrupt event register (EXTI_SWIER)"]
pub mod swier;
#[doc = "PR (rw) register accessor: Pending register (EXTI_PR)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pr`]
module"]
#[doc(alias = "PR")]
pub type Pr = crate::Reg<pr::PrSpec>;
#[doc = "Pending register (EXTI_PR)"]
pub mod pr;
