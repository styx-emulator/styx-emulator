// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    _reserved0: [u8; 0x04],
    sai_acr1: SaiAcr1,
    sai_acr2: SaiAcr2,
    sai_afrcr: SaiAfrcr,
    sai_aslotr: SaiAslotr,
    sai_aim: SaiAim,
    sai_asr: SaiAsr,
    sai_aclrfr: SaiAclrfr,
    sai_adr: SaiAdr,
    sai_bcr1: SaiBcr1,
    sai_bcr2: SaiBcr2,
    sai_bfrcr: SaiBfrcr,
    sai_bslotr: SaiBslotr,
    sai_bim: SaiBim,
    sai_bsr: SaiBsr,
    sai_bclrfr: SaiBclrfr,
    sai_bdr: SaiBdr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x04 - SAI AConfiguration register 1"]
    #[inline(always)]
    pub const fn sai_acr1(&self) -> &SaiAcr1 {
        &self.sai_acr1
    }
    #[doc = "0x08 - SAI AConfiguration register 2"]
    #[inline(always)]
    pub const fn sai_acr2(&self) -> &SaiAcr2 {
        &self.sai_acr2
    }
    #[doc = "0x0c - SAI AFrame configuration register"]
    #[inline(always)]
    pub const fn sai_afrcr(&self) -> &SaiAfrcr {
        &self.sai_afrcr
    }
    #[doc = "0x10 - SAI ASlot register"]
    #[inline(always)]
    pub const fn sai_aslotr(&self) -> &SaiAslotr {
        &self.sai_aslotr
    }
    #[doc = "0x14 - SAI AInterrupt mask register2"]
    #[inline(always)]
    pub const fn sai_aim(&self) -> &SaiAim {
        &self.sai_aim
    }
    #[doc = "0x18 - SAI AStatus register"]
    #[inline(always)]
    pub const fn sai_asr(&self) -> &SaiAsr {
        &self.sai_asr
    }
    #[doc = "0x1c - SAI AClear flag register"]
    #[inline(always)]
    pub const fn sai_aclrfr(&self) -> &SaiAclrfr {
        &self.sai_aclrfr
    }
    #[doc = "0x20 - SAI AData register"]
    #[inline(always)]
    pub const fn sai_adr(&self) -> &SaiAdr {
        &self.sai_adr
    }
    #[doc = "0x24 - SAI BConfiguration register 1"]
    #[inline(always)]
    pub const fn sai_bcr1(&self) -> &SaiBcr1 {
        &self.sai_bcr1
    }
    #[doc = "0x28 - SAI BConfiguration register 2"]
    #[inline(always)]
    pub const fn sai_bcr2(&self) -> &SaiBcr2 {
        &self.sai_bcr2
    }
    #[doc = "0x2c - SAI BFrame configuration register"]
    #[inline(always)]
    pub const fn sai_bfrcr(&self) -> &SaiBfrcr {
        &self.sai_bfrcr
    }
    #[doc = "0x30 - SAI BSlot register"]
    #[inline(always)]
    pub const fn sai_bslotr(&self) -> &SaiBslotr {
        &self.sai_bslotr
    }
    #[doc = "0x34 - SAI BInterrupt mask register2"]
    #[inline(always)]
    pub const fn sai_bim(&self) -> &SaiBim {
        &self.sai_bim
    }
    #[doc = "0x38 - SAI BStatus register"]
    #[inline(always)]
    pub const fn sai_bsr(&self) -> &SaiBsr {
        &self.sai_bsr
    }
    #[doc = "0x3c - SAI BClear flag register"]
    #[inline(always)]
    pub const fn sai_bclrfr(&self) -> &SaiBclrfr {
        &self.sai_bclrfr
    }
    #[doc = "0x40 - SAI BData register"]
    #[inline(always)]
    pub const fn sai_bdr(&self) -> &SaiBdr {
        &self.sai_bdr
    }
}
#[doc = "SAI_ACR1 (rw) register accessor: SAI AConfiguration register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_acr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_acr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_acr1`]
module"]
#[doc(alias = "SAI_ACR1")]
pub type SaiAcr1 = crate::Reg<sai_acr1::SaiAcr1Spec>;
#[doc = "SAI AConfiguration register 1"]
pub mod sai_acr1;
#[doc = "SAI_BCR1 (rw) register accessor: SAI BConfiguration register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bcr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bcr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bcr1`]
module"]
#[doc(alias = "SAI_BCR1")]
pub type SaiBcr1 = crate::Reg<sai_bcr1::SaiBcr1Spec>;
#[doc = "SAI BConfiguration register 1"]
pub mod sai_bcr1;
#[doc = "SAI_ACR2 (rw) register accessor: SAI AConfiguration register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_acr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_acr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_acr2`]
module"]
#[doc(alias = "SAI_ACR2")]
pub type SaiAcr2 = crate::Reg<sai_acr2::SaiAcr2Spec>;
#[doc = "SAI AConfiguration register 2"]
pub mod sai_acr2;
#[doc = "SAI_BCR2 (rw) register accessor: SAI BConfiguration register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bcr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bcr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bcr2`]
module"]
#[doc(alias = "SAI_BCR2")]
pub type SaiBcr2 = crate::Reg<sai_bcr2::SaiBcr2Spec>;
#[doc = "SAI BConfiguration register 2"]
pub mod sai_bcr2;
#[doc = "SAI_AFRCR (rw) register accessor: SAI AFrame configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_afrcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_afrcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_afrcr`]
module"]
#[doc(alias = "SAI_AFRCR")]
pub type SaiAfrcr = crate::Reg<sai_afrcr::SaiAfrcrSpec>;
#[doc = "SAI AFrame configuration register"]
pub mod sai_afrcr;
#[doc = "SAI_BFRCR (rw) register accessor: SAI BFrame configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bfrcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bfrcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bfrcr`]
module"]
#[doc(alias = "SAI_BFRCR")]
pub type SaiBfrcr = crate::Reg<sai_bfrcr::SaiBfrcrSpec>;
#[doc = "SAI BFrame configuration register"]
pub mod sai_bfrcr;
#[doc = "SAI_ASLOTR (rw) register accessor: SAI ASlot register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_aslotr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_aslotr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_aslotr`]
module"]
#[doc(alias = "SAI_ASLOTR")]
pub type SaiAslotr = crate::Reg<sai_aslotr::SaiAslotrSpec>;
#[doc = "SAI ASlot register"]
pub mod sai_aslotr;
#[doc = "SAI_BSLOTR (rw) register accessor: SAI BSlot register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bslotr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bslotr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bslotr`]
module"]
#[doc(alias = "SAI_BSLOTR")]
pub type SaiBslotr = crate::Reg<sai_bslotr::SaiBslotrSpec>;
#[doc = "SAI BSlot register"]
pub mod sai_bslotr;
#[doc = "SAI_AIM (rw) register accessor: SAI AInterrupt mask register2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_aim::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_aim::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_aim`]
module"]
#[doc(alias = "SAI_AIM")]
pub type SaiAim = crate::Reg<sai_aim::SaiAimSpec>;
#[doc = "SAI AInterrupt mask register2"]
pub mod sai_aim;
#[doc = "SAI_BIM (rw) register accessor: SAI BInterrupt mask register2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bim::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bim::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bim`]
module"]
#[doc(alias = "SAI_BIM")]
pub type SaiBim = crate::Reg<sai_bim::SaiBimSpec>;
#[doc = "SAI BInterrupt mask register2"]
pub mod sai_bim;
#[doc = "SAI_ASR (r) register accessor: SAI AStatus register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_asr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_asr`]
module"]
#[doc(alias = "SAI_ASR")]
pub type SaiAsr = crate::Reg<sai_asr::SaiAsrSpec>;
#[doc = "SAI AStatus register"]
pub mod sai_asr;
#[doc = "SAI_BSR (r) register accessor: SAI BStatus register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bsr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bsr`]
module"]
#[doc(alias = "SAI_BSR")]
pub type SaiBsr = crate::Reg<sai_bsr::SaiBsrSpec>;
#[doc = "SAI BStatus register"]
pub mod sai_bsr;
#[doc = "SAI_ACLRFR (rw) register accessor: SAI AClear flag register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_aclrfr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_aclrfr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_aclrfr`]
module"]
#[doc(alias = "SAI_ACLRFR")]
pub type SaiAclrfr = crate::Reg<sai_aclrfr::SaiAclrfrSpec>;
#[doc = "SAI AClear flag register"]
pub mod sai_aclrfr;
#[doc = "SAI_BCLRFR (rw) register accessor: SAI BClear flag register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bclrfr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bclrfr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bclrfr`]
module"]
#[doc(alias = "SAI_BCLRFR")]
pub type SaiBclrfr = crate::Reg<sai_bclrfr::SaiBclrfrSpec>;
#[doc = "SAI BClear flag register"]
pub mod sai_bclrfr;
#[doc = "SAI_ADR (rw) register accessor: SAI AData register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_adr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_adr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_adr`]
module"]
#[doc(alias = "SAI_ADR")]
pub type SaiAdr = crate::Reg<sai_adr::SaiAdrSpec>;
#[doc = "SAI AData register"]
pub mod sai_adr;
#[doc = "SAI_BDR (rw) register accessor: SAI BData register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bdr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bdr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sai_bdr`]
module"]
#[doc(alias = "SAI_BDR")]
pub type SaiBdr = crate::Reg<sai_bdr::SaiBdrSpec>;
#[doc = "SAI BData register"]
pub mod sai_bdr;
