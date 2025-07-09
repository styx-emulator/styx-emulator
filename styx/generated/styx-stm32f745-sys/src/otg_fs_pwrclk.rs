// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    otg_fs_pcgcctl: OtgFsPcgcctl,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_FS power and clock gating control register (OTG_FS_PCGCCTL)"]
    #[inline(always)]
    pub const fn otg_fs_pcgcctl(&self) -> &OtgFsPcgcctl {
        &self.otg_fs_pcgcctl
    }
}
#[doc = "OTG_FS_PCGCCTL (rw) register accessor: OTG_FS power and clock gating control register (OTG_FS_PCGCCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_pcgcctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_pcgcctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_pcgcctl`]
module"]
#[doc(alias = "OTG_FS_PCGCCTL")]
pub type OtgFsPcgcctl = crate::Reg<otg_fs_pcgcctl::OtgFsPcgcctlSpec>;
#[doc = "OTG_FS power and clock gating control register (OTG_FS_PCGCCTL)"]
pub mod otg_fs_pcgcctl;
