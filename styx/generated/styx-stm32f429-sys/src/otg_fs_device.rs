// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    fs_dcfg: FsDcfg,
    fs_dctl: FsDctl,
    fs_dsts: FsDsts,
    _reserved3: [u8; 0x04],
    fs_diepmsk: FsDiepmsk,
    fs_doepmsk: FsDoepmsk,
    fs_daint: FsDaint,
    fs_daintmsk: FsDaintmsk,
    _reserved7: [u8; 0x08],
    dvbusdis: Dvbusdis,
    dvbuspulse: Dvbuspulse,
    _reserved9: [u8; 0x04],
    diepempmsk: Diepempmsk,
    _reserved10: [u8; 0xc8],
    fs_diepctl0: FsDiepctl0,
    _reserved11: [u8; 0x04],
    diepint0: Diepint0,
    _reserved12: [u8; 0x04],
    dieptsiz0: Dieptsiz0,
    _reserved13: [u8; 0x04],
    dtxfsts0: Dtxfsts0,
    _reserved14: [u8; 0x04],
    diepctl1: Diepctl1,
    _reserved15: [u8; 0x04],
    diepint1: Diepint1,
    _reserved16: [u8; 0x04],
    dieptsiz1: Dieptsiz1,
    _reserved17: [u8; 0x04],
    dtxfsts1: Dtxfsts1,
    _reserved18: [u8; 0x04],
    diepctl2: Diepctl2,
    _reserved19: [u8; 0x04],
    diepint2: Diepint2,
    _reserved20: [u8; 0x04],
    dieptsiz2: Dieptsiz2,
    _reserved21: [u8; 0x04],
    dtxfsts2: Dtxfsts2,
    _reserved22: [u8; 0x04],
    diepctl3: Diepctl3,
    _reserved23: [u8; 0x04],
    diepint3: Diepint3,
    _reserved24: [u8; 0x04],
    dieptsiz3: Dieptsiz3,
    _reserved25: [u8; 0x04],
    dtxfsts3: Dtxfsts3,
    _reserved26: [u8; 0x0184],
    doepctl0: Doepctl0,
    _reserved27: [u8; 0x04],
    doepint0: Doepint0,
    _reserved28: [u8; 0x04],
    doeptsiz0: Doeptsiz0,
    _reserved29: [u8; 0x0c],
    doepctl1: Doepctl1,
    _reserved30: [u8; 0x04],
    doepint1: Doepint1,
    _reserved31: [u8; 0x04],
    doeptsiz1: Doeptsiz1,
    _reserved32: [u8; 0x0c],
    doepctl2: Doepctl2,
    _reserved33: [u8; 0x04],
    doepint2: Doepint2,
    _reserved34: [u8; 0x04],
    doeptsiz2: Doeptsiz2,
    _reserved35: [u8; 0x0c],
    doepctl3: Doepctl3,
    _reserved36: [u8; 0x04],
    doepint3: Doepint3,
    _reserved37: [u8; 0x04],
    doeptsiz3: Doeptsiz3,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_FS device configuration register (OTG_FS_DCFG)"]
    #[inline(always)]
    pub const fn fs_dcfg(&self) -> &FsDcfg {
        &self.fs_dcfg
    }
    #[doc = "0x04 - OTG_FS device control register (OTG_FS_DCTL)"]
    #[inline(always)]
    pub const fn fs_dctl(&self) -> &FsDctl {
        &self.fs_dctl
    }
    #[doc = "0x08 - OTG_FS device status register (OTG_FS_DSTS)"]
    #[inline(always)]
    pub const fn fs_dsts(&self) -> &FsDsts {
        &self.fs_dsts
    }
    #[doc = "0x10 - OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)"]
    #[inline(always)]
    pub const fn fs_diepmsk(&self) -> &FsDiepmsk {
        &self.fs_diepmsk
    }
    #[doc = "0x14 - OTG_FS device OUT endpoint common interrupt mask register (OTG_FS_DOEPMSK)"]
    #[inline(always)]
    pub const fn fs_doepmsk(&self) -> &FsDoepmsk {
        &self.fs_doepmsk
    }
    #[doc = "0x18 - OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)"]
    #[inline(always)]
    pub const fn fs_daint(&self) -> &FsDaint {
        &self.fs_daint
    }
    #[doc = "0x1c - OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)"]
    #[inline(always)]
    pub const fn fs_daintmsk(&self) -> &FsDaintmsk {
        &self.fs_daintmsk
    }
    #[doc = "0x28 - OTG_FS device VBUS discharge time register"]
    #[inline(always)]
    pub const fn dvbusdis(&self) -> &Dvbusdis {
        &self.dvbusdis
    }
    #[doc = "0x2c - OTG_FS device VBUS pulsing time register"]
    #[inline(always)]
    pub const fn dvbuspulse(&self) -> &Dvbuspulse {
        &self.dvbuspulse
    }
    #[doc = "0x34 - OTG_FS device IN endpoint FIFO empty interrupt mask register"]
    #[inline(always)]
    pub const fn diepempmsk(&self) -> &Diepempmsk {
        &self.diepempmsk
    }
    #[doc = "0x100 - OTG_FS device control IN endpoint 0 control register (OTG_FS_DIEPCTL0)"]
    #[inline(always)]
    pub const fn fs_diepctl0(&self) -> &FsDiepctl0 {
        &self.fs_diepctl0
    }
    #[doc = "0x108 - device endpoint-x interrupt register"]
    #[inline(always)]
    pub const fn diepint0(&self) -> &Diepint0 {
        &self.diepint0
    }
    #[doc = "0x110 - device endpoint-0 transfer size register"]
    #[inline(always)]
    pub const fn dieptsiz0(&self) -> &Dieptsiz0 {
        &self.dieptsiz0
    }
    #[doc = "0x118 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn dtxfsts0(&self) -> &Dtxfsts0 {
        &self.dtxfsts0
    }
    #[doc = "0x120 - OTG device endpoint-1 control register"]
    #[inline(always)]
    pub const fn diepctl1(&self) -> &Diepctl1 {
        &self.diepctl1
    }
    #[doc = "0x128 - device endpoint-1 interrupt register"]
    #[inline(always)]
    pub const fn diepint1(&self) -> &Diepint1 {
        &self.diepint1
    }
    #[doc = "0x130 - device endpoint-1 transfer size register"]
    #[inline(always)]
    pub const fn dieptsiz1(&self) -> &Dieptsiz1 {
        &self.dieptsiz1
    }
    #[doc = "0x138 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn dtxfsts1(&self) -> &Dtxfsts1 {
        &self.dtxfsts1
    }
    #[doc = "0x140 - OTG device endpoint-2 control register"]
    #[inline(always)]
    pub const fn diepctl2(&self) -> &Diepctl2 {
        &self.diepctl2
    }
    #[doc = "0x148 - device endpoint-2 interrupt register"]
    #[inline(always)]
    pub const fn diepint2(&self) -> &Diepint2 {
        &self.diepint2
    }
    #[doc = "0x150 - device endpoint-2 transfer size register"]
    #[inline(always)]
    pub const fn dieptsiz2(&self) -> &Dieptsiz2 {
        &self.dieptsiz2
    }
    #[doc = "0x158 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn dtxfsts2(&self) -> &Dtxfsts2 {
        &self.dtxfsts2
    }
    #[doc = "0x160 - OTG device endpoint-3 control register"]
    #[inline(always)]
    pub const fn diepctl3(&self) -> &Diepctl3 {
        &self.diepctl3
    }
    #[doc = "0x168 - device endpoint-3 interrupt register"]
    #[inline(always)]
    pub const fn diepint3(&self) -> &Diepint3 {
        &self.diepint3
    }
    #[doc = "0x170 - device endpoint-3 transfer size register"]
    #[inline(always)]
    pub const fn dieptsiz3(&self) -> &Dieptsiz3 {
        &self.dieptsiz3
    }
    #[doc = "0x178 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn dtxfsts3(&self) -> &Dtxfsts3 {
        &self.dtxfsts3
    }
    #[doc = "0x300 - device endpoint-0 control register"]
    #[inline(always)]
    pub const fn doepctl0(&self) -> &Doepctl0 {
        &self.doepctl0
    }
    #[doc = "0x308 - device endpoint-0 interrupt register"]
    #[inline(always)]
    pub const fn doepint0(&self) -> &Doepint0 {
        &self.doepint0
    }
    #[doc = "0x310 - device OUT endpoint-0 transfer size register"]
    #[inline(always)]
    pub const fn doeptsiz0(&self) -> &Doeptsiz0 {
        &self.doeptsiz0
    }
    #[doc = "0x320 - device endpoint-1 control register"]
    #[inline(always)]
    pub const fn doepctl1(&self) -> &Doepctl1 {
        &self.doepctl1
    }
    #[doc = "0x328 - device endpoint-1 interrupt register"]
    #[inline(always)]
    pub const fn doepint1(&self) -> &Doepint1 {
        &self.doepint1
    }
    #[doc = "0x330 - device OUT endpoint-1 transfer size register"]
    #[inline(always)]
    pub const fn doeptsiz1(&self) -> &Doeptsiz1 {
        &self.doeptsiz1
    }
    #[doc = "0x340 - device endpoint-2 control register"]
    #[inline(always)]
    pub const fn doepctl2(&self) -> &Doepctl2 {
        &self.doepctl2
    }
    #[doc = "0x348 - device endpoint-2 interrupt register"]
    #[inline(always)]
    pub const fn doepint2(&self) -> &Doepint2 {
        &self.doepint2
    }
    #[doc = "0x350 - device OUT endpoint-2 transfer size register"]
    #[inline(always)]
    pub const fn doeptsiz2(&self) -> &Doeptsiz2 {
        &self.doeptsiz2
    }
    #[doc = "0x360 - device endpoint-3 control register"]
    #[inline(always)]
    pub const fn doepctl3(&self) -> &Doepctl3 {
        &self.doepctl3
    }
    #[doc = "0x368 - device endpoint-3 interrupt register"]
    #[inline(always)]
    pub const fn doepint3(&self) -> &Doepint3 {
        &self.doepint3
    }
    #[doc = "0x370 - device OUT endpoint-3 transfer size register"]
    #[inline(always)]
    pub const fn doeptsiz3(&self) -> &Doeptsiz3 {
        &self.doeptsiz3
    }
}
#[doc = "FS_DCFG (rw) register accessor: OTG_FS device configuration register (OTG_FS_DCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_dcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_dcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_dcfg`]
module"]
#[doc(alias = "FS_DCFG")]
pub type FsDcfg = crate::Reg<fs_dcfg::FsDcfgSpec>;
#[doc = "OTG_FS device configuration register (OTG_FS_DCFG)"]
pub mod fs_dcfg;
#[doc = "FS_DCTL (rw) register accessor: OTG_FS device control register (OTG_FS_DCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_dctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_dctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_dctl`]
module"]
#[doc(alias = "FS_DCTL")]
pub type FsDctl = crate::Reg<fs_dctl::FsDctlSpec>;
#[doc = "OTG_FS device control register (OTG_FS_DCTL)"]
pub mod fs_dctl;
#[doc = "FS_DSTS (r) register accessor: OTG_FS device status register (OTG_FS_DSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_dsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_dsts`]
module"]
#[doc(alias = "FS_DSTS")]
pub type FsDsts = crate::Reg<fs_dsts::FsDstsSpec>;
#[doc = "OTG_FS device status register (OTG_FS_DSTS)"]
pub mod fs_dsts;
#[doc = "FS_DIEPMSK (rw) register accessor: OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_diepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_diepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_diepmsk`]
module"]
#[doc(alias = "FS_DIEPMSK")]
pub type FsDiepmsk = crate::Reg<fs_diepmsk::FsDiepmskSpec>;
#[doc = "OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)"]
pub mod fs_diepmsk;
#[doc = "FS_DOEPMSK (rw) register accessor: OTG_FS device OUT endpoint common interrupt mask register (OTG_FS_DOEPMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_doepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_doepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_doepmsk`]
module"]
#[doc(alias = "FS_DOEPMSK")]
pub type FsDoepmsk = crate::Reg<fs_doepmsk::FsDoepmskSpec>;
#[doc = "OTG_FS device OUT endpoint common interrupt mask register (OTG_FS_DOEPMSK)"]
pub mod fs_doepmsk;
#[doc = "FS_DAINT (r) register accessor: OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_daint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_daint`]
module"]
#[doc(alias = "FS_DAINT")]
pub type FsDaint = crate::Reg<fs_daint::FsDaintSpec>;
#[doc = "OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)"]
pub mod fs_daint;
#[doc = "FS_DAINTMSK (rw) register accessor: OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_daintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_daintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_daintmsk`]
module"]
#[doc(alias = "FS_DAINTMSK")]
pub type FsDaintmsk = crate::Reg<fs_daintmsk::FsDaintmskSpec>;
#[doc = "OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)"]
pub mod fs_daintmsk;
#[doc = "DVBUSDIS (rw) register accessor: OTG_FS device VBUS discharge time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dvbusdis::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dvbusdis::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dvbusdis`]
module"]
#[doc(alias = "DVBUSDIS")]
pub type Dvbusdis = crate::Reg<dvbusdis::DvbusdisSpec>;
#[doc = "OTG_FS device VBUS discharge time register"]
pub mod dvbusdis;
#[doc = "DVBUSPULSE (rw) register accessor: OTG_FS device VBUS pulsing time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dvbuspulse::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dvbuspulse::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dvbuspulse`]
module"]
#[doc(alias = "DVBUSPULSE")]
pub type Dvbuspulse = crate::Reg<dvbuspulse::DvbuspulseSpec>;
#[doc = "OTG_FS device VBUS pulsing time register"]
pub mod dvbuspulse;
#[doc = "DIEPEMPMSK (rw) register accessor: OTG_FS device IN endpoint FIFO empty interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepempmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepempmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepempmsk`]
module"]
#[doc(alias = "DIEPEMPMSK")]
pub type Diepempmsk = crate::Reg<diepempmsk::DiepempmskSpec>;
#[doc = "OTG_FS device IN endpoint FIFO empty interrupt mask register"]
pub mod diepempmsk;
#[doc = "FS_DIEPCTL0 (rw) register accessor: OTG_FS device control IN endpoint 0 control register (OTG_FS_DIEPCTL0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_diepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_diepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_diepctl0`]
module"]
#[doc(alias = "FS_DIEPCTL0")]
pub type FsDiepctl0 = crate::Reg<fs_diepctl0::FsDiepctl0Spec>;
#[doc = "OTG_FS device control IN endpoint 0 control register (OTG_FS_DIEPCTL0)"]
pub mod fs_diepctl0;
#[doc = "DIEPCTL1 (rw) register accessor: OTG device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepctl1`]
module"]
#[doc(alias = "DIEPCTL1")]
pub type Diepctl1 = crate::Reg<diepctl1::Diepctl1Spec>;
#[doc = "OTG device endpoint-1 control register"]
pub mod diepctl1;
#[doc = "DIEPCTL2 (rw) register accessor: OTG device endpoint-2 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepctl2`]
module"]
#[doc(alias = "DIEPCTL2")]
pub type Diepctl2 = crate::Reg<diepctl2::Diepctl2Spec>;
#[doc = "OTG device endpoint-2 control register"]
pub mod diepctl2;
#[doc = "DIEPCTL3 (rw) register accessor: OTG device endpoint-3 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepctl3`]
module"]
#[doc(alias = "DIEPCTL3")]
pub type Diepctl3 = crate::Reg<diepctl3::Diepctl3Spec>;
#[doc = "OTG device endpoint-3 control register"]
pub mod diepctl3;
#[doc = "DOEPCTL0 (rw) register accessor: device endpoint-0 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepctl0`]
module"]
#[doc(alias = "DOEPCTL0")]
pub type Doepctl0 = crate::Reg<doepctl0::Doepctl0Spec>;
#[doc = "device endpoint-0 control register"]
pub mod doepctl0;
#[doc = "DOEPCTL1 (rw) register accessor: device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepctl1`]
module"]
#[doc(alias = "DOEPCTL1")]
pub type Doepctl1 = crate::Reg<doepctl1::Doepctl1Spec>;
#[doc = "device endpoint-1 control register"]
pub mod doepctl1;
#[doc = "DOEPCTL2 (rw) register accessor: device endpoint-2 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepctl2`]
module"]
#[doc(alias = "DOEPCTL2")]
pub type Doepctl2 = crate::Reg<doepctl2::Doepctl2Spec>;
#[doc = "device endpoint-2 control register"]
pub mod doepctl2;
#[doc = "DOEPCTL3 (rw) register accessor: device endpoint-3 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepctl3`]
module"]
#[doc(alias = "DOEPCTL3")]
pub type Doepctl3 = crate::Reg<doepctl3::Doepctl3Spec>;
#[doc = "device endpoint-3 control register"]
pub mod doepctl3;
#[doc = "DIEPINT0 (rw) register accessor: device endpoint-x interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepint0`]
module"]
#[doc(alias = "DIEPINT0")]
pub type Diepint0 = crate::Reg<diepint0::Diepint0Spec>;
#[doc = "device endpoint-x interrupt register"]
pub mod diepint0;
#[doc = "DIEPINT1 (rw) register accessor: device endpoint-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepint1`]
module"]
#[doc(alias = "DIEPINT1")]
pub type Diepint1 = crate::Reg<diepint1::Diepint1Spec>;
#[doc = "device endpoint-1 interrupt register"]
pub mod diepint1;
#[doc = "DIEPINT2 (rw) register accessor: device endpoint-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepint2`]
module"]
#[doc(alias = "DIEPINT2")]
pub type Diepint2 = crate::Reg<diepint2::Diepint2Spec>;
#[doc = "device endpoint-2 interrupt register"]
pub mod diepint2;
#[doc = "DIEPINT3 (rw) register accessor: device endpoint-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`diepint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`diepint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@diepint3`]
module"]
#[doc(alias = "DIEPINT3")]
pub type Diepint3 = crate::Reg<diepint3::Diepint3Spec>;
#[doc = "device endpoint-3 interrupt register"]
pub mod diepint3;
#[doc = "DOEPINT0 (rw) register accessor: device endpoint-0 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepint0`]
module"]
#[doc(alias = "DOEPINT0")]
pub type Doepint0 = crate::Reg<doepint0::Doepint0Spec>;
#[doc = "device endpoint-0 interrupt register"]
pub mod doepint0;
#[doc = "DOEPINT1 (rw) register accessor: device endpoint-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepint1`]
module"]
#[doc(alias = "DOEPINT1")]
pub type Doepint1 = crate::Reg<doepint1::Doepint1Spec>;
#[doc = "device endpoint-1 interrupt register"]
pub mod doepint1;
#[doc = "DOEPINT2 (rw) register accessor: device endpoint-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepint2`]
module"]
#[doc(alias = "DOEPINT2")]
pub type Doepint2 = crate::Reg<doepint2::Doepint2Spec>;
#[doc = "device endpoint-2 interrupt register"]
pub mod doepint2;
#[doc = "DOEPINT3 (rw) register accessor: device endpoint-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doepint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doepint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doepint3`]
module"]
#[doc(alias = "DOEPINT3")]
pub type Doepint3 = crate::Reg<doepint3::Doepint3Spec>;
#[doc = "device endpoint-3 interrupt register"]
pub mod doepint3;
#[doc = "DIEPTSIZ0 (rw) register accessor: device endpoint-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dieptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dieptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dieptsiz0`]
module"]
#[doc(alias = "DIEPTSIZ0")]
pub type Dieptsiz0 = crate::Reg<dieptsiz0::Dieptsiz0Spec>;
#[doc = "device endpoint-0 transfer size register"]
pub mod dieptsiz0;
#[doc = "DOEPTSIZ0 (rw) register accessor: device OUT endpoint-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doeptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doeptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doeptsiz0`]
module"]
#[doc(alias = "DOEPTSIZ0")]
pub type Doeptsiz0 = crate::Reg<doeptsiz0::Doeptsiz0Spec>;
#[doc = "device OUT endpoint-0 transfer size register"]
pub mod doeptsiz0;
#[doc = "DIEPTSIZ1 (rw) register accessor: device endpoint-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dieptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dieptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dieptsiz1`]
module"]
#[doc(alias = "DIEPTSIZ1")]
pub type Dieptsiz1 = crate::Reg<dieptsiz1::Dieptsiz1Spec>;
#[doc = "device endpoint-1 transfer size register"]
pub mod dieptsiz1;
#[doc = "DIEPTSIZ2 (rw) register accessor: device endpoint-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dieptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dieptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dieptsiz2`]
module"]
#[doc(alias = "DIEPTSIZ2")]
pub type Dieptsiz2 = crate::Reg<dieptsiz2::Dieptsiz2Spec>;
#[doc = "device endpoint-2 transfer size register"]
pub mod dieptsiz2;
#[doc = "DIEPTSIZ3 (rw) register accessor: device endpoint-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dieptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dieptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dieptsiz3`]
module"]
#[doc(alias = "DIEPTSIZ3")]
pub type Dieptsiz3 = crate::Reg<dieptsiz3::Dieptsiz3Spec>;
#[doc = "device endpoint-3 transfer size register"]
pub mod dieptsiz3;
#[doc = "DTXFSTS0 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtxfsts0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dtxfsts0`]
module"]
#[doc(alias = "DTXFSTS0")]
pub type Dtxfsts0 = crate::Reg<dtxfsts0::Dtxfsts0Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod dtxfsts0;
#[doc = "DTXFSTS1 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtxfsts1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dtxfsts1`]
module"]
#[doc(alias = "DTXFSTS1")]
pub type Dtxfsts1 = crate::Reg<dtxfsts1::Dtxfsts1Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod dtxfsts1;
#[doc = "DTXFSTS2 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtxfsts2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dtxfsts2`]
module"]
#[doc(alias = "DTXFSTS2")]
pub type Dtxfsts2 = crate::Reg<dtxfsts2::Dtxfsts2Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod dtxfsts2;
#[doc = "DTXFSTS3 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtxfsts3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dtxfsts3`]
module"]
#[doc(alias = "DTXFSTS3")]
pub type Dtxfsts3 = crate::Reg<dtxfsts3::Dtxfsts3Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod dtxfsts3;
#[doc = "DOEPTSIZ1 (rw) register accessor: device OUT endpoint-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doeptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doeptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doeptsiz1`]
module"]
#[doc(alias = "DOEPTSIZ1")]
pub type Doeptsiz1 = crate::Reg<doeptsiz1::Doeptsiz1Spec>;
#[doc = "device OUT endpoint-1 transfer size register"]
pub mod doeptsiz1;
#[doc = "DOEPTSIZ2 (rw) register accessor: device OUT endpoint-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doeptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doeptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doeptsiz2`]
module"]
#[doc(alias = "DOEPTSIZ2")]
pub type Doeptsiz2 = crate::Reg<doeptsiz2::Doeptsiz2Spec>;
#[doc = "device OUT endpoint-2 transfer size register"]
pub mod doeptsiz2;
#[doc = "DOEPTSIZ3 (rw) register accessor: device OUT endpoint-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`doeptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`doeptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@doeptsiz3`]
module"]
#[doc(alias = "DOEPTSIZ3")]
pub type Doeptsiz3 = crate::Reg<doeptsiz3::Doeptsiz3Spec>;
#[doc = "device OUT endpoint-3 transfer size register"]
pub mod doeptsiz3;
