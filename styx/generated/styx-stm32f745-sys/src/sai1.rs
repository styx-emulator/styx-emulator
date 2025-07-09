// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    gcr: Gcr,
    acr1: Acr1,
    acr2: Acr2,
    afrcr: Afrcr,
    aslotr: Aslotr,
    aim: Aim,
    asr: Asr,
    aclrfr: Aclrfr,
    adr: Adr,
    bcr1: Bcr1,
    bcr2: Bcr2,
    bfrcr: Bfrcr,
    bslotr: Bslotr,
    bim: Bim,
    bsr: Bsr,
    bclrfr: Bclrfr,
    bdr: Bdr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Global configuration register"]
    #[inline(always)]
    pub const fn gcr(&self) -> &Gcr {
        &self.gcr
    }
    #[doc = "0x04 - AConfiguration register 1"]
    #[inline(always)]
    pub const fn acr1(&self) -> &Acr1 {
        &self.acr1
    }
    #[doc = "0x08 - AConfiguration register 2"]
    #[inline(always)]
    pub const fn acr2(&self) -> &Acr2 {
        &self.acr2
    }
    #[doc = "0x0c - AFRCR"]
    #[inline(always)]
    pub const fn afrcr(&self) -> &Afrcr {
        &self.afrcr
    }
    #[doc = "0x10 - ASlot register"]
    #[inline(always)]
    pub const fn aslotr(&self) -> &Aslotr {
        &self.aslotr
    }
    #[doc = "0x14 - AInterrupt mask register2"]
    #[inline(always)]
    pub const fn aim(&self) -> &Aim {
        &self.aim
    }
    #[doc = "0x18 - AStatus register"]
    #[inline(always)]
    pub const fn asr(&self) -> &Asr {
        &self.asr
    }
    #[doc = "0x1c - AClear flag register"]
    #[inline(always)]
    pub const fn aclrfr(&self) -> &Aclrfr {
        &self.aclrfr
    }
    #[doc = "0x20 - AData register"]
    #[inline(always)]
    pub const fn adr(&self) -> &Adr {
        &self.adr
    }
    #[doc = "0x24 - BConfiguration register 1"]
    #[inline(always)]
    pub const fn bcr1(&self) -> &Bcr1 {
        &self.bcr1
    }
    #[doc = "0x28 - BConfiguration register 2"]
    #[inline(always)]
    pub const fn bcr2(&self) -> &Bcr2 {
        &self.bcr2
    }
    #[doc = "0x2c - BFRCR"]
    #[inline(always)]
    pub const fn bfrcr(&self) -> &Bfrcr {
        &self.bfrcr
    }
    #[doc = "0x30 - BSlot register"]
    #[inline(always)]
    pub const fn bslotr(&self) -> &Bslotr {
        &self.bslotr
    }
    #[doc = "0x34 - BInterrupt mask register2"]
    #[inline(always)]
    pub const fn bim(&self) -> &Bim {
        &self.bim
    }
    #[doc = "0x38 - BStatus register"]
    #[inline(always)]
    pub const fn bsr(&self) -> &Bsr {
        &self.bsr
    }
    #[doc = "0x3c - BClear flag register"]
    #[inline(always)]
    pub const fn bclrfr(&self) -> &Bclrfr {
        &self.bclrfr
    }
    #[doc = "0x40 - BData register"]
    #[inline(always)]
    pub const fn bdr(&self) -> &Bdr {
        &self.bdr
    }
}
#[doc = "BCR1 (rw) register accessor: BConfiguration register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bcr1`]
module"]
#[doc(alias = "BCR1")]
pub type Bcr1 = crate::Reg<bcr1::Bcr1Spec>;
#[doc = "BConfiguration register 1"]
pub mod bcr1;
#[doc = "BCR2 (rw) register accessor: BConfiguration register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bcr2`]
module"]
#[doc(alias = "BCR2")]
pub type Bcr2 = crate::Reg<bcr2::Bcr2Spec>;
#[doc = "BConfiguration register 2"]
pub mod bcr2;
#[doc = "BFRCR (rw) register accessor: BFRCR\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bfrcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bfrcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bfrcr`]
module"]
#[doc(alias = "BFRCR")]
pub type Bfrcr = crate::Reg<bfrcr::BfrcrSpec>;
#[doc = "BFRCR"]
pub mod bfrcr;
#[doc = "BSLOTR (rw) register accessor: BSlot register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bslotr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bslotr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bslotr`]
module"]
#[doc(alias = "BSLOTR")]
pub type Bslotr = crate::Reg<bslotr::BslotrSpec>;
#[doc = "BSlot register"]
pub mod bslotr;
#[doc = "BIM (rw) register accessor: BInterrupt mask register2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bim::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bim::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bim`]
module"]
#[doc(alias = "BIM")]
pub type Bim = crate::Reg<bim::BimSpec>;
#[doc = "BInterrupt mask register2"]
pub mod bim;
#[doc = "BSR (r) register accessor: BStatus register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bsr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bsr`]
module"]
#[doc(alias = "BSR")]
pub type Bsr = crate::Reg<bsr::BsrSpec>;
#[doc = "BStatus register"]
pub mod bsr;
#[doc = "BCLRFR (w) register accessor: BClear flag register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bclrfr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bclrfr`]
module"]
#[doc(alias = "BCLRFR")]
pub type Bclrfr = crate::Reg<bclrfr::BclrfrSpec>;
#[doc = "BClear flag register"]
pub mod bclrfr;
#[doc = "BDR (rw) register accessor: BData register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bdr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bdr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bdr`]
module"]
#[doc(alias = "BDR")]
pub type Bdr = crate::Reg<bdr::BdrSpec>;
#[doc = "BData register"]
pub mod bdr;
#[doc = "ACR1 (rw) register accessor: AConfiguration register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`acr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`acr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@acr1`]
module"]
#[doc(alias = "ACR1")]
pub type Acr1 = crate::Reg<acr1::Acr1Spec>;
#[doc = "AConfiguration register 1"]
pub mod acr1;
#[doc = "ACR2 (rw) register accessor: AConfiguration register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`acr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`acr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@acr2`]
module"]
#[doc(alias = "ACR2")]
pub type Acr2 = crate::Reg<acr2::Acr2Spec>;
#[doc = "AConfiguration register 2"]
pub mod acr2;
#[doc = "AFRCR (rw) register accessor: AFRCR\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`afrcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`afrcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@afrcr`]
module"]
#[doc(alias = "AFRCR")]
pub type Afrcr = crate::Reg<afrcr::AfrcrSpec>;
#[doc = "AFRCR"]
pub mod afrcr;
#[doc = "ASLOTR (rw) register accessor: ASlot register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aslotr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aslotr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@aslotr`]
module"]
#[doc(alias = "ASLOTR")]
pub type Aslotr = crate::Reg<aslotr::AslotrSpec>;
#[doc = "ASlot register"]
pub mod aslotr;
#[doc = "AIM (rw) register accessor: AInterrupt mask register2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aim::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aim::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@aim`]
module"]
#[doc(alias = "AIM")]
pub type Aim = crate::Reg<aim::AimSpec>;
#[doc = "AInterrupt mask register2"]
pub mod aim;
#[doc = "ASR (rw) register accessor: AStatus register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`asr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`asr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@asr`]
module"]
#[doc(alias = "ASR")]
pub type Asr = crate::Reg<asr::AsrSpec>;
#[doc = "AStatus register"]
pub mod asr;
#[doc = "ACLRFR (rw) register accessor: AClear flag register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aclrfr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aclrfr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@aclrfr`]
module"]
#[doc(alias = "ACLRFR")]
pub type Aclrfr = crate::Reg<aclrfr::AclrfrSpec>;
#[doc = "AClear flag register"]
pub mod aclrfr;
#[doc = "ADR (rw) register accessor: AData register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`adr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`adr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@adr`]
module"]
#[doc(alias = "ADR")]
pub type Adr = crate::Reg<adr::AdrSpec>;
#[doc = "AData register"]
pub mod adr;
#[doc = "GCR (rw) register accessor: Global configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gcr`]
module"]
#[doc(alias = "GCR")]
pub type Gcr = crate::Reg<gcr::GcrSpec>;
#[doc = "Global configuration register"]
pub mod gcr;
