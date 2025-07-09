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
    otg_fs_dcfg: OtgFsDcfg,
    otg_fs_dctl: OtgFsDctl,
    otg_fs_dsts: OtgFsDsts,
    _reserved3: [u8; 0x04],
    otg_fs_diepmsk: OtgFsDiepmsk,
    otg_fs_doepmsk: OtgFsDoepmsk,
    otg_fs_daint: OtgFsDaint,
    otg_fs_daintmsk: OtgFsDaintmsk,
    _reserved7: [u8; 0x08],
    otg_fs_dvbusdis: OtgFsDvbusdis,
    otg_fs_dvbuspulse: OtgFsDvbuspulse,
    _reserved9: [u8; 0x04],
    otg_fs_diepempmsk: OtgFsDiepempmsk,
    _reserved10: [u8; 0xc8],
    otg_fs_diepctl0: OtgFsDiepctl0,
    _reserved11: [u8; 0x04],
    otg_fs_diepint0: OtgFsDiepint0,
    _reserved12: [u8; 0x04],
    otg_fs_dieptsiz0: OtgFsDieptsiz0,
    _reserved13: [u8; 0x04],
    otg_fs_dtxfsts0: OtgFsDtxfsts0,
    _reserved14: [u8; 0x04],
    otg_fs_diepctl1: OtgFsDiepctl1,
    _reserved15: [u8; 0x04],
    otg_fs_diepint1: OtgFsDiepint1,
    _reserved16: [u8; 0x04],
    otg_fs_dieptsiz1: OtgFsDieptsiz1,
    _reserved17: [u8; 0x04],
    otg_fs_dtxfsts1: OtgFsDtxfsts1,
    _reserved18: [u8; 0x04],
    otg_fs_diepctl2: OtgFsDiepctl2,
    _reserved19: [u8; 0x04],
    otg_fs_diepint2: OtgFsDiepint2,
    _reserved20: [u8; 0x04],
    otg_fs_dieptsiz2: OtgFsDieptsiz2,
    _reserved21: [u8; 0x04],
    otg_fs_dtxfsts2: OtgFsDtxfsts2,
    _reserved22: [u8; 0x04],
    otg_fs_diepctl3: OtgFsDiepctl3,
    _reserved23: [u8; 0x04],
    otg_fs_diepint3: OtgFsDiepint3,
    _reserved24: [u8; 0x04],
    otg_fs_dieptsiz3: OtgFsDieptsiz3,
    _reserved25: [u8; 0x04],
    otg_fs_dtxfsts3: OtgFsDtxfsts3,
    _reserved26: [u8; 0x04],
    otg_fs_diepctl4: OtgFsDiepctl4,
    _reserved27: [u8; 0x04],
    otg_fs_diepint4: OtgFsDiepint4,
    _reserved28: [u8; 0x08],
    otg_fs_dieptsiz4: OtgFsDieptsiz4,
    _reserved29: [u8; 0x04],
    otg_fs_dtxfsts4: OtgFsDtxfsts4,
    otg_fs_diepctl5: OtgFsDiepctl5,
    _reserved31: [u8; 0x04],
    otg_fs_diepint5: OtgFsDiepint5,
    _reserved32: [u8; 0x04],
    otg_fs_dieptsiz55: OtgFsDieptsiz55,
    _reserved33: [u8; 0x04],
    otg_fs_dtxfsts55: OtgFsDtxfsts55,
    _reserved34: [u8; 0x0144],
    otg_fs_doepctl0: OtgFsDoepctl0,
    _reserved35: [u8; 0x04],
    otg_fs_doepint0: OtgFsDoepint0,
    _reserved36: [u8; 0x04],
    otg_fs_doeptsiz0: OtgFsDoeptsiz0,
    _reserved37: [u8; 0x0c],
    otg_fs_doepctl1: OtgFsDoepctl1,
    _reserved38: [u8; 0x04],
    otg_fs_doepint1: OtgFsDoepint1,
    _reserved39: [u8; 0x04],
    otg_fs_doeptsiz1: OtgFsDoeptsiz1,
    _reserved40: [u8; 0x0c],
    otg_fs_doepctl2: OtgFsDoepctl2,
    _reserved41: [u8; 0x04],
    otg_fs_doepint2: OtgFsDoepint2,
    _reserved42: [u8; 0x04],
    otg_fs_doeptsiz2: OtgFsDoeptsiz2,
    _reserved43: [u8; 0x0c],
    otg_fs_doepctl3: OtgFsDoepctl3,
    _reserved44: [u8; 0x04],
    otg_fs_doepint3: OtgFsDoepint3,
    _reserved45: [u8; 0x04],
    otg_fs_doeptsiz3: OtgFsDoeptsiz3,
    _reserved46: [u8; 0x04],
    otg_fs_doepctl4: OtgFsDoepctl4,
    _reserved47: [u8; 0x04],
    otg_fs_doepint4: OtgFsDoepint4,
    _reserved48: [u8; 0x04],
    otg_fs_doeptsiz4: OtgFsDoeptsiz4,
    _reserved49: [u8; 0x04],
    otg_fs_doepctl5: OtgFsDoepctl5,
    _reserved50: [u8; 0x04],
    otg_fs_doepint5: OtgFsDoepint5,
    _reserved51: [u8; 0x04],
    otg_fs_doeptsiz5: OtgFsDoeptsiz5,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_FS device configuration register (OTG_FS_DCFG)"]
    #[inline(always)]
    pub const fn otg_fs_dcfg(&self) -> &OtgFsDcfg {
        &self.otg_fs_dcfg
    }
    #[doc = "0x04 - OTG_FS device control register (OTG_FS_DCTL)"]
    #[inline(always)]
    pub const fn otg_fs_dctl(&self) -> &OtgFsDctl {
        &self.otg_fs_dctl
    }
    #[doc = "0x08 - OTG_FS device status register (OTG_FS_DSTS)"]
    #[inline(always)]
    pub const fn otg_fs_dsts(&self) -> &OtgFsDsts {
        &self.otg_fs_dsts
    }
    #[doc = "0x10 - OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)"]
    #[inline(always)]
    pub const fn otg_fs_diepmsk(&self) -> &OtgFsDiepmsk {
        &self.otg_fs_diepmsk
    }
    #[doc = "0x14 - OTG_FS device OUT endpoint common interrupt mask register (OTG_FS_DOEPMSK)"]
    #[inline(always)]
    pub const fn otg_fs_doepmsk(&self) -> &OtgFsDoepmsk {
        &self.otg_fs_doepmsk
    }
    #[doc = "0x18 - OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)"]
    #[inline(always)]
    pub const fn otg_fs_daint(&self) -> &OtgFsDaint {
        &self.otg_fs_daint
    }
    #[doc = "0x1c - OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)"]
    #[inline(always)]
    pub const fn otg_fs_daintmsk(&self) -> &OtgFsDaintmsk {
        &self.otg_fs_daintmsk
    }
    #[doc = "0x28 - OTG_FS device VBUS discharge time register"]
    #[inline(always)]
    pub const fn otg_fs_dvbusdis(&self) -> &OtgFsDvbusdis {
        &self.otg_fs_dvbusdis
    }
    #[doc = "0x2c - OTG_FS device VBUS pulsing time register"]
    #[inline(always)]
    pub const fn otg_fs_dvbuspulse(&self) -> &OtgFsDvbuspulse {
        &self.otg_fs_dvbuspulse
    }
    #[doc = "0x34 - OTG_FS device IN endpoint FIFO empty interrupt mask register"]
    #[inline(always)]
    pub const fn otg_fs_diepempmsk(&self) -> &OtgFsDiepempmsk {
        &self.otg_fs_diepempmsk
    }
    #[doc = "0x100 - OTG_FS device control IN endpoint 0 control register (OTG_FS_DIEPCTL0)"]
    #[inline(always)]
    pub const fn otg_fs_diepctl0(&self) -> &OtgFsDiepctl0 {
        &self.otg_fs_diepctl0
    }
    #[doc = "0x108 - device endpoint-x interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_diepint0(&self) -> &OtgFsDiepint0 {
        &self.otg_fs_diepint0
    }
    #[doc = "0x110 - device endpoint-0 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_dieptsiz0(&self) -> &OtgFsDieptsiz0 {
        &self.otg_fs_dieptsiz0
    }
    #[doc = "0x118 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_fs_dtxfsts0(&self) -> &OtgFsDtxfsts0 {
        &self.otg_fs_dtxfsts0
    }
    #[doc = "0x120 - OTG device endpoint-1 control register"]
    #[inline(always)]
    pub const fn otg_fs_diepctl1(&self) -> &OtgFsDiepctl1 {
        &self.otg_fs_diepctl1
    }
    #[doc = "0x128 - device endpoint-1 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_diepint1(&self) -> &OtgFsDiepint1 {
        &self.otg_fs_diepint1
    }
    #[doc = "0x130 - device endpoint-1 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_dieptsiz1(&self) -> &OtgFsDieptsiz1 {
        &self.otg_fs_dieptsiz1
    }
    #[doc = "0x138 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_fs_dtxfsts1(&self) -> &OtgFsDtxfsts1 {
        &self.otg_fs_dtxfsts1
    }
    #[doc = "0x140 - OTG device endpoint-2 control register"]
    #[inline(always)]
    pub const fn otg_fs_diepctl2(&self) -> &OtgFsDiepctl2 {
        &self.otg_fs_diepctl2
    }
    #[doc = "0x148 - device endpoint-2 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_diepint2(&self) -> &OtgFsDiepint2 {
        &self.otg_fs_diepint2
    }
    #[doc = "0x150 - device endpoint-2 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_dieptsiz2(&self) -> &OtgFsDieptsiz2 {
        &self.otg_fs_dieptsiz2
    }
    #[doc = "0x158 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_fs_dtxfsts2(&self) -> &OtgFsDtxfsts2 {
        &self.otg_fs_dtxfsts2
    }
    #[doc = "0x160 - OTG device endpoint-3 control register"]
    #[inline(always)]
    pub const fn otg_fs_diepctl3(&self) -> &OtgFsDiepctl3 {
        &self.otg_fs_diepctl3
    }
    #[doc = "0x168 - device endpoint-3 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_diepint3(&self) -> &OtgFsDiepint3 {
        &self.otg_fs_diepint3
    }
    #[doc = "0x170 - device endpoint-3 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_dieptsiz3(&self) -> &OtgFsDieptsiz3 {
        &self.otg_fs_dieptsiz3
    }
    #[doc = "0x178 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_fs_dtxfsts3(&self) -> &OtgFsDtxfsts3 {
        &self.otg_fs_dtxfsts3
    }
    #[doc = "0x180 - OTG device endpoint-4 control register"]
    #[inline(always)]
    pub const fn otg_fs_diepctl4(&self) -> &OtgFsDiepctl4 {
        &self.otg_fs_diepctl4
    }
    #[doc = "0x188 - device endpoint-4 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_diepint4(&self) -> &OtgFsDiepint4 {
        &self.otg_fs_diepint4
    }
    #[doc = "0x194 - device endpoint-4 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_dieptsiz4(&self) -> &OtgFsDieptsiz4 {
        &self.otg_fs_dieptsiz4
    }
    #[doc = "0x19c - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_fs_dtxfsts4(&self) -> &OtgFsDtxfsts4 {
        &self.otg_fs_dtxfsts4
    }
    #[doc = "0x1a0 - OTG device endpoint-5 control register"]
    #[inline(always)]
    pub const fn otg_fs_diepctl5(&self) -> &OtgFsDiepctl5 {
        &self.otg_fs_diepctl5
    }
    #[doc = "0x1a8 - device endpoint-5 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_diepint5(&self) -> &OtgFsDiepint5 {
        &self.otg_fs_diepint5
    }
    #[doc = "0x1b0 - device endpoint-5 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_dieptsiz55(&self) -> &OtgFsDieptsiz55 {
        &self.otg_fs_dieptsiz55
    }
    #[doc = "0x1b8 - OTG_FS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_fs_dtxfsts55(&self) -> &OtgFsDtxfsts55 {
        &self.otg_fs_dtxfsts55
    }
    #[doc = "0x300 - device endpoint-0 control register"]
    #[inline(always)]
    pub const fn otg_fs_doepctl0(&self) -> &OtgFsDoepctl0 {
        &self.otg_fs_doepctl0
    }
    #[doc = "0x308 - device endpoint-0 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_doepint0(&self) -> &OtgFsDoepint0 {
        &self.otg_fs_doepint0
    }
    #[doc = "0x310 - device OUT endpoint-0 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_doeptsiz0(&self) -> &OtgFsDoeptsiz0 {
        &self.otg_fs_doeptsiz0
    }
    #[doc = "0x320 - device endpoint-1 control register"]
    #[inline(always)]
    pub const fn otg_fs_doepctl1(&self) -> &OtgFsDoepctl1 {
        &self.otg_fs_doepctl1
    }
    #[doc = "0x328 - device endpoint-1 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_doepint1(&self) -> &OtgFsDoepint1 {
        &self.otg_fs_doepint1
    }
    #[doc = "0x330 - device OUT endpoint-1 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_doeptsiz1(&self) -> &OtgFsDoeptsiz1 {
        &self.otg_fs_doeptsiz1
    }
    #[doc = "0x340 - device endpoint-2 control register"]
    #[inline(always)]
    pub const fn otg_fs_doepctl2(&self) -> &OtgFsDoepctl2 {
        &self.otg_fs_doepctl2
    }
    #[doc = "0x348 - device endpoint-2 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_doepint2(&self) -> &OtgFsDoepint2 {
        &self.otg_fs_doepint2
    }
    #[doc = "0x350 - device OUT endpoint-2 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_doeptsiz2(&self) -> &OtgFsDoeptsiz2 {
        &self.otg_fs_doeptsiz2
    }
    #[doc = "0x360 - device endpoint-3 control register"]
    #[inline(always)]
    pub const fn otg_fs_doepctl3(&self) -> &OtgFsDoepctl3 {
        &self.otg_fs_doepctl3
    }
    #[doc = "0x368 - device endpoint-3 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_doepint3(&self) -> &OtgFsDoepint3 {
        &self.otg_fs_doepint3
    }
    #[doc = "0x370 - device OUT endpoint-3 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_doeptsiz3(&self) -> &OtgFsDoeptsiz3 {
        &self.otg_fs_doeptsiz3
    }
    #[doc = "0x378 - device endpoint-4 control register"]
    #[inline(always)]
    pub const fn otg_fs_doepctl4(&self) -> &OtgFsDoepctl4 {
        &self.otg_fs_doepctl4
    }
    #[doc = "0x380 - device endpoint-4 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_doepint4(&self) -> &OtgFsDoepint4 {
        &self.otg_fs_doepint4
    }
    #[doc = "0x388 - device OUT endpoint-4 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_doeptsiz4(&self) -> &OtgFsDoeptsiz4 {
        &self.otg_fs_doeptsiz4
    }
    #[doc = "0x390 - device endpoint-5 control register"]
    #[inline(always)]
    pub const fn otg_fs_doepctl5(&self) -> &OtgFsDoepctl5 {
        &self.otg_fs_doepctl5
    }
    #[doc = "0x398 - device endpoint-5 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_doepint5(&self) -> &OtgFsDoepint5 {
        &self.otg_fs_doepint5
    }
    #[doc = "0x3a0 - device OUT endpoint-5 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_doeptsiz5(&self) -> &OtgFsDoeptsiz5 {
        &self.otg_fs_doeptsiz5
    }
}
#[doc = "OTG_FS_DCFG (rw) register accessor: OTG_FS device configuration register (OTG_FS_DCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dcfg`]
module"]
#[doc(alias = "OTG_FS_DCFG")]
pub type OtgFsDcfg = crate::Reg<otg_fs_dcfg::OtgFsDcfgSpec>;
#[doc = "OTG_FS device configuration register (OTG_FS_DCFG)"]
pub mod otg_fs_dcfg;
#[doc = "OTG_FS_DCTL (rw) register accessor: OTG_FS device control register (OTG_FS_DCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dctl`]
module"]
#[doc(alias = "OTG_FS_DCTL")]
pub type OtgFsDctl = crate::Reg<otg_fs_dctl::OtgFsDctlSpec>;
#[doc = "OTG_FS device control register (OTG_FS_DCTL)"]
pub mod otg_fs_dctl;
#[doc = "OTG_FS_DSTS (r) register accessor: OTG_FS device status register (OTG_FS_DSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dsts`]
module"]
#[doc(alias = "OTG_FS_DSTS")]
pub type OtgFsDsts = crate::Reg<otg_fs_dsts::OtgFsDstsSpec>;
#[doc = "OTG_FS device status register (OTG_FS_DSTS)"]
pub mod otg_fs_dsts;
#[doc = "OTG_FS_DIEPMSK (rw) register accessor: OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepmsk`]
module"]
#[doc(alias = "OTG_FS_DIEPMSK")]
pub type OtgFsDiepmsk = crate::Reg<otg_fs_diepmsk::OtgFsDiepmskSpec>;
#[doc = "OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)"]
pub mod otg_fs_diepmsk;
#[doc = "OTG_FS_DOEPMSK (rw) register accessor: OTG_FS device OUT endpoint common interrupt mask register (OTG_FS_DOEPMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepmsk`]
module"]
#[doc(alias = "OTG_FS_DOEPMSK")]
pub type OtgFsDoepmsk = crate::Reg<otg_fs_doepmsk::OtgFsDoepmskSpec>;
#[doc = "OTG_FS device OUT endpoint common interrupt mask register (OTG_FS_DOEPMSK)"]
pub mod otg_fs_doepmsk;
#[doc = "OTG_FS_DAINT (r) register accessor: OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_daint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_daint`]
module"]
#[doc(alias = "OTG_FS_DAINT")]
pub type OtgFsDaint = crate::Reg<otg_fs_daint::OtgFsDaintSpec>;
#[doc = "OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)"]
pub mod otg_fs_daint;
#[doc = "OTG_FS_DAINTMSK (rw) register accessor: OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_daintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_daintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_daintmsk`]
module"]
#[doc(alias = "OTG_FS_DAINTMSK")]
pub type OtgFsDaintmsk = crate::Reg<otg_fs_daintmsk::OtgFsDaintmskSpec>;
#[doc = "OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)"]
pub mod otg_fs_daintmsk;
#[doc = "OTG_FS_DVBUSDIS (rw) register accessor: OTG_FS device VBUS discharge time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dvbusdis::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dvbusdis::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dvbusdis`]
module"]
#[doc(alias = "OTG_FS_DVBUSDIS")]
pub type OtgFsDvbusdis = crate::Reg<otg_fs_dvbusdis::OtgFsDvbusdisSpec>;
#[doc = "OTG_FS device VBUS discharge time register"]
pub mod otg_fs_dvbusdis;
#[doc = "OTG_FS_DVBUSPULSE (rw) register accessor: OTG_FS device VBUS pulsing time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dvbuspulse::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dvbuspulse::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dvbuspulse`]
module"]
#[doc(alias = "OTG_FS_DVBUSPULSE")]
pub type OtgFsDvbuspulse = crate::Reg<otg_fs_dvbuspulse::OtgFsDvbuspulseSpec>;
#[doc = "OTG_FS device VBUS pulsing time register"]
pub mod otg_fs_dvbuspulse;
#[doc = "OTG_FS_DIEPEMPMSK (rw) register accessor: OTG_FS device IN endpoint FIFO empty interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepempmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepempmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepempmsk`]
module"]
#[doc(alias = "OTG_FS_DIEPEMPMSK")]
pub type OtgFsDiepempmsk = crate::Reg<otg_fs_diepempmsk::OtgFsDiepempmskSpec>;
#[doc = "OTG_FS device IN endpoint FIFO empty interrupt mask register"]
pub mod otg_fs_diepempmsk;
#[doc = "OTG_FS_DIEPCTL0 (rw) register accessor: OTG_FS device control IN endpoint 0 control register (OTG_FS_DIEPCTL0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepctl0`]
module"]
#[doc(alias = "OTG_FS_DIEPCTL0")]
pub type OtgFsDiepctl0 = crate::Reg<otg_fs_diepctl0::OtgFsDiepctl0Spec>;
#[doc = "OTG_FS device control IN endpoint 0 control register (OTG_FS_DIEPCTL0)"]
pub mod otg_fs_diepctl0;
#[doc = "OTG_FS_DIEPCTL1 (rw) register accessor: OTG device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepctl1`]
module"]
#[doc(alias = "OTG_FS_DIEPCTL1")]
pub type OtgFsDiepctl1 = crate::Reg<otg_fs_diepctl1::OtgFsDiepctl1Spec>;
#[doc = "OTG device endpoint-1 control register"]
pub mod otg_fs_diepctl1;
#[doc = "OTG_FS_DIEPCTL2 (rw) register accessor: OTG device endpoint-2 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepctl2`]
module"]
#[doc(alias = "OTG_FS_DIEPCTL2")]
pub type OtgFsDiepctl2 = crate::Reg<otg_fs_diepctl2::OtgFsDiepctl2Spec>;
#[doc = "OTG device endpoint-2 control register"]
pub mod otg_fs_diepctl2;
#[doc = "OTG_FS_DIEPCTL3 (rw) register accessor: OTG device endpoint-3 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepctl3`]
module"]
#[doc(alias = "OTG_FS_DIEPCTL3")]
pub type OtgFsDiepctl3 = crate::Reg<otg_fs_diepctl3::OtgFsDiepctl3Spec>;
#[doc = "OTG device endpoint-3 control register"]
pub mod otg_fs_diepctl3;
#[doc = "OTG_FS_DOEPCTL0 (rw) register accessor: device endpoint-0 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepctl0`]
module"]
#[doc(alias = "OTG_FS_DOEPCTL0")]
pub type OtgFsDoepctl0 = crate::Reg<otg_fs_doepctl0::OtgFsDoepctl0Spec>;
#[doc = "device endpoint-0 control register"]
pub mod otg_fs_doepctl0;
#[doc = "OTG_FS_DOEPCTL1 (rw) register accessor: device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepctl1`]
module"]
#[doc(alias = "OTG_FS_DOEPCTL1")]
pub type OtgFsDoepctl1 = crate::Reg<otg_fs_doepctl1::OtgFsDoepctl1Spec>;
#[doc = "device endpoint-1 control register"]
pub mod otg_fs_doepctl1;
#[doc = "OTG_FS_DOEPCTL2 (rw) register accessor: device endpoint-2 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepctl2`]
module"]
#[doc(alias = "OTG_FS_DOEPCTL2")]
pub type OtgFsDoepctl2 = crate::Reg<otg_fs_doepctl2::OtgFsDoepctl2Spec>;
#[doc = "device endpoint-2 control register"]
pub mod otg_fs_doepctl2;
#[doc = "OTG_FS_DOEPCTL3 (rw) register accessor: device endpoint-3 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepctl3`]
module"]
#[doc(alias = "OTG_FS_DOEPCTL3")]
pub type OtgFsDoepctl3 = crate::Reg<otg_fs_doepctl3::OtgFsDoepctl3Spec>;
#[doc = "device endpoint-3 control register"]
pub mod otg_fs_doepctl3;
#[doc = "OTG_FS_DIEPINT0 (rw) register accessor: device endpoint-x interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepint0`]
module"]
#[doc(alias = "OTG_FS_DIEPINT0")]
pub type OtgFsDiepint0 = crate::Reg<otg_fs_diepint0::OtgFsDiepint0Spec>;
#[doc = "device endpoint-x interrupt register"]
pub mod otg_fs_diepint0;
#[doc = "OTG_FS_DIEPINT1 (rw) register accessor: device endpoint-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepint1`]
module"]
#[doc(alias = "OTG_FS_DIEPINT1")]
pub type OtgFsDiepint1 = crate::Reg<otg_fs_diepint1::OtgFsDiepint1Spec>;
#[doc = "device endpoint-1 interrupt register"]
pub mod otg_fs_diepint1;
#[doc = "OTG_FS_DIEPINT2 (rw) register accessor: device endpoint-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepint2`]
module"]
#[doc(alias = "OTG_FS_DIEPINT2")]
pub type OtgFsDiepint2 = crate::Reg<otg_fs_diepint2::OtgFsDiepint2Spec>;
#[doc = "device endpoint-2 interrupt register"]
pub mod otg_fs_diepint2;
#[doc = "OTG_FS_DIEPINT3 (rw) register accessor: device endpoint-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepint3`]
module"]
#[doc(alias = "OTG_FS_DIEPINT3")]
pub type OtgFsDiepint3 = crate::Reg<otg_fs_diepint3::OtgFsDiepint3Spec>;
#[doc = "device endpoint-3 interrupt register"]
pub mod otg_fs_diepint3;
#[doc = "OTG_FS_DOEPINT0 (rw) register accessor: device endpoint-0 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepint0`]
module"]
#[doc(alias = "OTG_FS_DOEPINT0")]
pub type OtgFsDoepint0 = crate::Reg<otg_fs_doepint0::OtgFsDoepint0Spec>;
#[doc = "device endpoint-0 interrupt register"]
pub mod otg_fs_doepint0;
#[doc = "OTG_FS_DOEPINT1 (rw) register accessor: device endpoint-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepint1`]
module"]
#[doc(alias = "OTG_FS_DOEPINT1")]
pub type OtgFsDoepint1 = crate::Reg<otg_fs_doepint1::OtgFsDoepint1Spec>;
#[doc = "device endpoint-1 interrupt register"]
pub mod otg_fs_doepint1;
#[doc = "OTG_FS_DOEPINT2 (rw) register accessor: device endpoint-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepint2`]
module"]
#[doc(alias = "OTG_FS_DOEPINT2")]
pub type OtgFsDoepint2 = crate::Reg<otg_fs_doepint2::OtgFsDoepint2Spec>;
#[doc = "device endpoint-2 interrupt register"]
pub mod otg_fs_doepint2;
#[doc = "OTG_FS_DOEPINT3 (rw) register accessor: device endpoint-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepint3`]
module"]
#[doc(alias = "OTG_FS_DOEPINT3")]
pub type OtgFsDoepint3 = crate::Reg<otg_fs_doepint3::OtgFsDoepint3Spec>;
#[doc = "device endpoint-3 interrupt register"]
pub mod otg_fs_doepint3;
#[doc = "OTG_FS_DIEPTSIZ0 (rw) register accessor: device endpoint-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptsiz0`]
module"]
#[doc(alias = "OTG_FS_DIEPTSIZ0")]
pub type OtgFsDieptsiz0 = crate::Reg<otg_fs_dieptsiz0::OtgFsDieptsiz0Spec>;
#[doc = "device endpoint-0 transfer size register"]
pub mod otg_fs_dieptsiz0;
#[doc = "OTG_FS_DOEPTSIZ0 (rw) register accessor: device OUT endpoint-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doeptsiz0`]
module"]
#[doc(alias = "OTG_FS_DOEPTSIZ0")]
pub type OtgFsDoeptsiz0 = crate::Reg<otg_fs_doeptsiz0::OtgFsDoeptsiz0Spec>;
#[doc = "device OUT endpoint-0 transfer size register"]
pub mod otg_fs_doeptsiz0;
#[doc = "OTG_FS_DIEPTSIZ1 (rw) register accessor: device endpoint-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptsiz1`]
module"]
#[doc(alias = "OTG_FS_DIEPTSIZ1")]
pub type OtgFsDieptsiz1 = crate::Reg<otg_fs_dieptsiz1::OtgFsDieptsiz1Spec>;
#[doc = "device endpoint-1 transfer size register"]
pub mod otg_fs_dieptsiz1;
#[doc = "OTG_FS_DIEPTSIZ2 (rw) register accessor: device endpoint-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptsiz2`]
module"]
#[doc(alias = "OTG_FS_DIEPTSIZ2")]
pub type OtgFsDieptsiz2 = crate::Reg<otg_fs_dieptsiz2::OtgFsDieptsiz2Spec>;
#[doc = "device endpoint-2 transfer size register"]
pub mod otg_fs_dieptsiz2;
#[doc = "OTG_FS_DIEPTSIZ3 (rw) register accessor: device endpoint-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptsiz3`]
module"]
#[doc(alias = "OTG_FS_DIEPTSIZ3")]
pub type OtgFsDieptsiz3 = crate::Reg<otg_fs_dieptsiz3::OtgFsDieptsiz3Spec>;
#[doc = "device endpoint-3 transfer size register"]
pub mod otg_fs_dieptsiz3;
#[doc = "OTG_FS_DTXFSTS0 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dtxfsts0`]
module"]
#[doc(alias = "OTG_FS_DTXFSTS0")]
pub type OtgFsDtxfsts0 = crate::Reg<otg_fs_dtxfsts0::OtgFsDtxfsts0Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod otg_fs_dtxfsts0;
#[doc = "OTG_FS_DTXFSTS1 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dtxfsts1`]
module"]
#[doc(alias = "OTG_FS_DTXFSTS1")]
pub type OtgFsDtxfsts1 = crate::Reg<otg_fs_dtxfsts1::OtgFsDtxfsts1Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod otg_fs_dtxfsts1;
#[doc = "OTG_FS_DTXFSTS2 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dtxfsts2`]
module"]
#[doc(alias = "OTG_FS_DTXFSTS2")]
pub type OtgFsDtxfsts2 = crate::Reg<otg_fs_dtxfsts2::OtgFsDtxfsts2Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod otg_fs_dtxfsts2;
#[doc = "OTG_FS_DTXFSTS3 (r) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dtxfsts3`]
module"]
#[doc(alias = "OTG_FS_DTXFSTS3")]
pub type OtgFsDtxfsts3 = crate::Reg<otg_fs_dtxfsts3::OtgFsDtxfsts3Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod otg_fs_dtxfsts3;
#[doc = "OTG_FS_DOEPTSIZ1 (rw) register accessor: device OUT endpoint-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doeptsiz1`]
module"]
#[doc(alias = "OTG_FS_DOEPTSIZ1")]
pub type OtgFsDoeptsiz1 = crate::Reg<otg_fs_doeptsiz1::OtgFsDoeptsiz1Spec>;
#[doc = "device OUT endpoint-1 transfer size register"]
pub mod otg_fs_doeptsiz1;
#[doc = "OTG_FS_DOEPTSIZ2 (rw) register accessor: device OUT endpoint-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doeptsiz2`]
module"]
#[doc(alias = "OTG_FS_DOEPTSIZ2")]
pub type OtgFsDoeptsiz2 = crate::Reg<otg_fs_doeptsiz2::OtgFsDoeptsiz2Spec>;
#[doc = "device OUT endpoint-2 transfer size register"]
pub mod otg_fs_doeptsiz2;
#[doc = "OTG_FS_DOEPTSIZ3 (rw) register accessor: device OUT endpoint-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doeptsiz3`]
module"]
#[doc(alias = "OTG_FS_DOEPTSIZ3")]
pub type OtgFsDoeptsiz3 = crate::Reg<otg_fs_doeptsiz3::OtgFsDoeptsiz3Spec>;
#[doc = "device OUT endpoint-3 transfer size register"]
pub mod otg_fs_doeptsiz3;
#[doc = "OTG_FS_DIEPCTL4 (rw) register accessor: OTG device endpoint-4 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepctl4`]
module"]
#[doc(alias = "OTG_FS_DIEPCTL4")]
pub type OtgFsDiepctl4 = crate::Reg<otg_fs_diepctl4::OtgFsDiepctl4Spec>;
#[doc = "OTG device endpoint-4 control register"]
pub mod otg_fs_diepctl4;
#[doc = "OTG_FS_DIEPINT4 (rw) register accessor: device endpoint-4 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepint4`]
module"]
#[doc(alias = "OTG_FS_DIEPINT4")]
pub type OtgFsDiepint4 = crate::Reg<otg_fs_diepint4::OtgFsDiepint4Spec>;
#[doc = "device endpoint-4 interrupt register"]
pub mod otg_fs_diepint4;
#[doc = "OTG_FS_DIEPTSIZ4 (rw) register accessor: device endpoint-4 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptsiz4`]
module"]
#[doc(alias = "OTG_FS_DIEPTSIZ4")]
pub type OtgFsDieptsiz4 = crate::Reg<otg_fs_dieptsiz4::OtgFsDieptsiz4Spec>;
#[doc = "device endpoint-4 transfer size register"]
pub mod otg_fs_dieptsiz4;
#[doc = "OTG_FS_DTXFSTS4 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dtxfsts4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dtxfsts4`]
module"]
#[doc(alias = "OTG_FS_DTXFSTS4")]
pub type OtgFsDtxfsts4 = crate::Reg<otg_fs_dtxfsts4::OtgFsDtxfsts4Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod otg_fs_dtxfsts4;
#[doc = "OTG_FS_DIEPCTL5 (rw) register accessor: OTG device endpoint-5 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepctl5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepctl5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepctl5`]
module"]
#[doc(alias = "OTG_FS_DIEPCTL5")]
pub type OtgFsDiepctl5 = crate::Reg<otg_fs_diepctl5::OtgFsDiepctl5Spec>;
#[doc = "OTG device endpoint-5 control register"]
pub mod otg_fs_diepctl5;
#[doc = "OTG_FS_DIEPINT5 (rw) register accessor: device endpoint-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_diepint5`]
module"]
#[doc(alias = "OTG_FS_DIEPINT5")]
pub type OtgFsDiepint5 = crate::Reg<otg_fs_diepint5::OtgFsDiepint5Spec>;
#[doc = "device endpoint-5 interrupt register"]
pub mod otg_fs_diepint5;
#[doc = "OTG_FS_DIEPTSIZ55 (rw) register accessor: device endpoint-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptsiz55::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptsiz55::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptsiz55`]
module"]
#[doc(alias = "OTG_FS_DIEPTSIZ55")]
pub type OtgFsDieptsiz55 = crate::Reg<otg_fs_dieptsiz55::OtgFsDieptsiz55Spec>;
#[doc = "device endpoint-5 transfer size register"]
pub mod otg_fs_dieptsiz55;
#[doc = "OTG_FS_DTXFSTS55 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts55::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dtxfsts55::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dtxfsts55`]
module"]
#[doc(alias = "OTG_FS_DTXFSTS55")]
pub type OtgFsDtxfsts55 = crate::Reg<otg_fs_dtxfsts55::OtgFsDtxfsts55Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO status register"]
pub mod otg_fs_dtxfsts55;
#[doc = "OTG_FS_DOEPCTL4 (rw) register accessor: device endpoint-4 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepctl4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepctl4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepctl4`]
module"]
#[doc(alias = "OTG_FS_DOEPCTL4")]
pub type OtgFsDoepctl4 = crate::Reg<otg_fs_doepctl4::OtgFsDoepctl4Spec>;
#[doc = "device endpoint-4 control register"]
pub mod otg_fs_doepctl4;
#[doc = "OTG_FS_DOEPINT4 (rw) register accessor: device endpoint-4 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepint4`]
module"]
#[doc(alias = "OTG_FS_DOEPINT4")]
pub type OtgFsDoepint4 = crate::Reg<otg_fs_doepint4::OtgFsDoepint4Spec>;
#[doc = "device endpoint-4 interrupt register"]
pub mod otg_fs_doepint4;
#[doc = "OTG_FS_DOEPTSIZ4 (rw) register accessor: device OUT endpoint-4 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doeptsiz4`]
module"]
#[doc(alias = "OTG_FS_DOEPTSIZ4")]
pub type OtgFsDoeptsiz4 = crate::Reg<otg_fs_doeptsiz4::OtgFsDoeptsiz4Spec>;
#[doc = "device OUT endpoint-4 transfer size register"]
pub mod otg_fs_doeptsiz4;
#[doc = "OTG_FS_DOEPCTL5 (rw) register accessor: device endpoint-5 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepctl5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepctl5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepctl5`]
module"]
#[doc(alias = "OTG_FS_DOEPCTL5")]
pub type OtgFsDoepctl5 = crate::Reg<otg_fs_doepctl5::OtgFsDoepctl5Spec>;
#[doc = "device endpoint-5 control register"]
pub mod otg_fs_doepctl5;
#[doc = "OTG_FS_DOEPINT5 (rw) register accessor: device endpoint-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doepint5`]
module"]
#[doc(alias = "OTG_FS_DOEPINT5")]
pub type OtgFsDoepint5 = crate::Reg<otg_fs_doepint5::OtgFsDoepint5Spec>;
#[doc = "device endpoint-5 interrupt register"]
pub mod otg_fs_doepint5;
#[doc = "OTG_FS_DOEPTSIZ5 (rw) register accessor: device OUT endpoint-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_doeptsiz5`]
module"]
#[doc(alias = "OTG_FS_DOEPTSIZ5")]
pub type OtgFsDoeptsiz5 = crate::Reg<otg_fs_doeptsiz5::OtgFsDoeptsiz5Spec>;
#[doc = "device OUT endpoint-5 transfer size register"]
pub mod otg_fs_doeptsiz5;
