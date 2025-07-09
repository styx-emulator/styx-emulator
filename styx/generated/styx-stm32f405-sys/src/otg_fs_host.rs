// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    fs_hcfg: FsHcfg,
    hfir: Hfir,
    fs_hfnum: FsHfnum,
    _reserved3: [u8; 0x04],
    fs_hptxsts: FsHptxsts,
    haint: Haint,
    haintmsk: Haintmsk,
    _reserved6: [u8; 0x24],
    fs_hprt: FsHprt,
    _reserved7: [u8; 0xbc],
    fs_hcchar0: FsHcchar0,
    _reserved8: [u8; 0x04],
    fs_hcint0: FsHcint0,
    fs_hcintmsk0: FsHcintmsk0,
    fs_hctsiz0: FsHctsiz0,
    _reserved11: [u8; 0x0c],
    fs_hcchar1: FsHcchar1,
    _reserved12: [u8; 0x04],
    fs_hcint1: FsHcint1,
    fs_hcintmsk1: FsHcintmsk1,
    fs_hctsiz1: FsHctsiz1,
    _reserved15: [u8; 0x0c],
    fs_hcchar2: FsHcchar2,
    _reserved16: [u8; 0x04],
    fs_hcint2: FsHcint2,
    fs_hcintmsk2: FsHcintmsk2,
    fs_hctsiz2: FsHctsiz2,
    _reserved19: [u8; 0x0c],
    fs_hcchar3: FsHcchar3,
    _reserved20: [u8; 0x04],
    fs_hcint3: FsHcint3,
    fs_hcintmsk3: FsHcintmsk3,
    fs_hctsiz3: FsHctsiz3,
    _reserved23: [u8; 0x0c],
    fs_hcchar4: FsHcchar4,
    _reserved24: [u8; 0x04],
    fs_hcint4: FsHcint4,
    fs_hcintmsk4: FsHcintmsk4,
    fs_hctsiz4: FsHctsiz4,
    _reserved27: [u8; 0x0c],
    fs_hcchar5: FsHcchar5,
    _reserved28: [u8; 0x04],
    fs_hcint5: FsHcint5,
    fs_hcintmsk5: FsHcintmsk5,
    fs_hctsiz5: FsHctsiz5,
    _reserved31: [u8; 0x0c],
    fs_hcchar6: FsHcchar6,
    _reserved32: [u8; 0x04],
    fs_hcint6: FsHcint6,
    fs_hcintmsk6: FsHcintmsk6,
    fs_hctsiz6: FsHctsiz6,
    _reserved35: [u8; 0x0c],
    fs_hcchar7: FsHcchar7,
    _reserved36: [u8; 0x04],
    fs_hcint7: FsHcint7,
    fs_hcintmsk7: FsHcintmsk7,
    fs_hctsiz7: FsHctsiz7,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_FS host configuration register (OTG_FS_HCFG)"]
    #[inline(always)]
    pub const fn fs_hcfg(&self) -> &FsHcfg {
        &self.fs_hcfg
    }
    #[doc = "0x04 - OTG_FS Host frame interval register"]
    #[inline(always)]
    pub const fn hfir(&self) -> &Hfir {
        &self.hfir
    }
    #[doc = "0x08 - OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)"]
    #[inline(always)]
    pub const fn fs_hfnum(&self) -> &FsHfnum {
        &self.fs_hfnum
    }
    #[doc = "0x10 - OTG_FS_Host periodic transmit FIFO/queue status register (OTG_FS_HPTXSTS)"]
    #[inline(always)]
    pub const fn fs_hptxsts(&self) -> &FsHptxsts {
        &self.fs_hptxsts
    }
    #[doc = "0x14 - OTG_FS Host all channels interrupt register"]
    #[inline(always)]
    pub const fn haint(&self) -> &Haint {
        &self.haint
    }
    #[doc = "0x18 - OTG_FS host all channels interrupt mask register"]
    #[inline(always)]
    pub const fn haintmsk(&self) -> &Haintmsk {
        &self.haintmsk
    }
    #[doc = "0x40 - OTG_FS host port control and status register (OTG_FS_HPRT)"]
    #[inline(always)]
    pub const fn fs_hprt(&self) -> &FsHprt {
        &self.fs_hprt
    }
    #[doc = "0x100 - OTG_FS host channel-0 characteristics register (OTG_FS_HCCHAR0)"]
    #[inline(always)]
    pub const fn fs_hcchar0(&self) -> &FsHcchar0 {
        &self.fs_hcchar0
    }
    #[doc = "0x108 - OTG_FS host channel-0 interrupt register (OTG_FS_HCINT0)"]
    #[inline(always)]
    pub const fn fs_hcint0(&self) -> &FsHcint0 {
        &self.fs_hcint0
    }
    #[doc = "0x10c - OTG_FS host channel-0 mask register (OTG_FS_HCINTMSK0)"]
    #[inline(always)]
    pub const fn fs_hcintmsk0(&self) -> &FsHcintmsk0 {
        &self.fs_hcintmsk0
    }
    #[doc = "0x110 - OTG_FS host channel-0 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz0(&self) -> &FsHctsiz0 {
        &self.fs_hctsiz0
    }
    #[doc = "0x120 - OTG_FS host channel-1 characteristics register (OTG_FS_HCCHAR1)"]
    #[inline(always)]
    pub const fn fs_hcchar1(&self) -> &FsHcchar1 {
        &self.fs_hcchar1
    }
    #[doc = "0x128 - OTG_FS host channel-1 interrupt register (OTG_FS_HCINT1)"]
    #[inline(always)]
    pub const fn fs_hcint1(&self) -> &FsHcint1 {
        &self.fs_hcint1
    }
    #[doc = "0x12c - OTG_FS host channel-1 mask register (OTG_FS_HCINTMSK1)"]
    #[inline(always)]
    pub const fn fs_hcintmsk1(&self) -> &FsHcintmsk1 {
        &self.fs_hcintmsk1
    }
    #[doc = "0x130 - OTG_FS host channel-1 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz1(&self) -> &FsHctsiz1 {
        &self.fs_hctsiz1
    }
    #[doc = "0x140 - OTG_FS host channel-2 characteristics register (OTG_FS_HCCHAR2)"]
    #[inline(always)]
    pub const fn fs_hcchar2(&self) -> &FsHcchar2 {
        &self.fs_hcchar2
    }
    #[doc = "0x148 - OTG_FS host channel-2 interrupt register (OTG_FS_HCINT2)"]
    #[inline(always)]
    pub const fn fs_hcint2(&self) -> &FsHcint2 {
        &self.fs_hcint2
    }
    #[doc = "0x14c - OTG_FS host channel-2 mask register (OTG_FS_HCINTMSK2)"]
    #[inline(always)]
    pub const fn fs_hcintmsk2(&self) -> &FsHcintmsk2 {
        &self.fs_hcintmsk2
    }
    #[doc = "0x150 - OTG_FS host channel-2 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz2(&self) -> &FsHctsiz2 {
        &self.fs_hctsiz2
    }
    #[doc = "0x160 - OTG_FS host channel-3 characteristics register (OTG_FS_HCCHAR3)"]
    #[inline(always)]
    pub const fn fs_hcchar3(&self) -> &FsHcchar3 {
        &self.fs_hcchar3
    }
    #[doc = "0x168 - OTG_FS host channel-3 interrupt register (OTG_FS_HCINT3)"]
    #[inline(always)]
    pub const fn fs_hcint3(&self) -> &FsHcint3 {
        &self.fs_hcint3
    }
    #[doc = "0x16c - OTG_FS host channel-3 mask register (OTG_FS_HCINTMSK3)"]
    #[inline(always)]
    pub const fn fs_hcintmsk3(&self) -> &FsHcintmsk3 {
        &self.fs_hcintmsk3
    }
    #[doc = "0x170 - OTG_FS host channel-3 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz3(&self) -> &FsHctsiz3 {
        &self.fs_hctsiz3
    }
    #[doc = "0x180 - OTG_FS host channel-4 characteristics register (OTG_FS_HCCHAR4)"]
    #[inline(always)]
    pub const fn fs_hcchar4(&self) -> &FsHcchar4 {
        &self.fs_hcchar4
    }
    #[doc = "0x188 - OTG_FS host channel-4 interrupt register (OTG_FS_HCINT4)"]
    #[inline(always)]
    pub const fn fs_hcint4(&self) -> &FsHcint4 {
        &self.fs_hcint4
    }
    #[doc = "0x18c - OTG_FS host channel-4 mask register (OTG_FS_HCINTMSK4)"]
    #[inline(always)]
    pub const fn fs_hcintmsk4(&self) -> &FsHcintmsk4 {
        &self.fs_hcintmsk4
    }
    #[doc = "0x190 - OTG_FS host channel-x transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz4(&self) -> &FsHctsiz4 {
        &self.fs_hctsiz4
    }
    #[doc = "0x1a0 - OTG_FS host channel-5 characteristics register (OTG_FS_HCCHAR5)"]
    #[inline(always)]
    pub const fn fs_hcchar5(&self) -> &FsHcchar5 {
        &self.fs_hcchar5
    }
    #[doc = "0x1a8 - OTG_FS host channel-5 interrupt register (OTG_FS_HCINT5)"]
    #[inline(always)]
    pub const fn fs_hcint5(&self) -> &FsHcint5 {
        &self.fs_hcint5
    }
    #[doc = "0x1ac - OTG_FS host channel-5 mask register (OTG_FS_HCINTMSK5)"]
    #[inline(always)]
    pub const fn fs_hcintmsk5(&self) -> &FsHcintmsk5 {
        &self.fs_hcintmsk5
    }
    #[doc = "0x1b0 - OTG_FS host channel-5 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz5(&self) -> &FsHctsiz5 {
        &self.fs_hctsiz5
    }
    #[doc = "0x1c0 - OTG_FS host channel-6 characteristics register (OTG_FS_HCCHAR6)"]
    #[inline(always)]
    pub const fn fs_hcchar6(&self) -> &FsHcchar6 {
        &self.fs_hcchar6
    }
    #[doc = "0x1c8 - OTG_FS host channel-6 interrupt register (OTG_FS_HCINT6)"]
    #[inline(always)]
    pub const fn fs_hcint6(&self) -> &FsHcint6 {
        &self.fs_hcint6
    }
    #[doc = "0x1cc - OTG_FS host channel-6 mask register (OTG_FS_HCINTMSK6)"]
    #[inline(always)]
    pub const fn fs_hcintmsk6(&self) -> &FsHcintmsk6 {
        &self.fs_hcintmsk6
    }
    #[doc = "0x1d0 - OTG_FS host channel-6 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz6(&self) -> &FsHctsiz6 {
        &self.fs_hctsiz6
    }
    #[doc = "0x1e0 - OTG_FS host channel-7 characteristics register (OTG_FS_HCCHAR7)"]
    #[inline(always)]
    pub const fn fs_hcchar7(&self) -> &FsHcchar7 {
        &self.fs_hcchar7
    }
    #[doc = "0x1e8 - OTG_FS host channel-7 interrupt register (OTG_FS_HCINT7)"]
    #[inline(always)]
    pub const fn fs_hcint7(&self) -> &FsHcint7 {
        &self.fs_hcint7
    }
    #[doc = "0x1ec - OTG_FS host channel-7 mask register (OTG_FS_HCINTMSK7)"]
    #[inline(always)]
    pub const fn fs_hcintmsk7(&self) -> &FsHcintmsk7 {
        &self.fs_hcintmsk7
    }
    #[doc = "0x1f0 - OTG_FS host channel-7 transfer size register"]
    #[inline(always)]
    pub const fn fs_hctsiz7(&self) -> &FsHctsiz7 {
        &self.fs_hctsiz7
    }
}
#[doc = "FS_HCFG (rw) register accessor: OTG_FS host configuration register (OTG_FS_HCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcfg`]
module"]
#[doc(alias = "FS_HCFG")]
pub type FsHcfg = crate::Reg<fs_hcfg::FsHcfgSpec>;
#[doc = "OTG_FS host configuration register (OTG_FS_HCFG)"]
pub mod fs_hcfg;
#[doc = "HFIR (rw) register accessor: OTG_FS Host frame interval register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hfir::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hfir::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hfir`]
module"]
#[doc(alias = "HFIR")]
pub type Hfir = crate::Reg<hfir::HfirSpec>;
#[doc = "OTG_FS Host frame interval register"]
pub mod hfir;
#[doc = "FS_HFNUM (r) register accessor: OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hfnum::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hfnum`]
module"]
#[doc(alias = "FS_HFNUM")]
pub type FsHfnum = crate::Reg<fs_hfnum::FsHfnumSpec>;
#[doc = "OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)"]
pub mod fs_hfnum;
#[doc = "FS_HPTXSTS (rw) register accessor: OTG_FS_Host periodic transmit FIFO/queue status register (OTG_FS_HPTXSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hptxsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hptxsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hptxsts`]
module"]
#[doc(alias = "FS_HPTXSTS")]
pub type FsHptxsts = crate::Reg<fs_hptxsts::FsHptxstsSpec>;
#[doc = "OTG_FS_Host periodic transmit FIFO/queue status register (OTG_FS_HPTXSTS)"]
pub mod fs_hptxsts;
#[doc = "HAINT (r) register accessor: OTG_FS Host all channels interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`haint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@haint`]
module"]
#[doc(alias = "HAINT")]
pub type Haint = crate::Reg<haint::HaintSpec>;
#[doc = "OTG_FS Host all channels interrupt register"]
pub mod haint;
#[doc = "HAINTMSK (rw) register accessor: OTG_FS host all channels interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`haintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`haintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@haintmsk`]
module"]
#[doc(alias = "HAINTMSK")]
pub type Haintmsk = crate::Reg<haintmsk::HaintmskSpec>;
#[doc = "OTG_FS host all channels interrupt mask register"]
pub mod haintmsk;
#[doc = "FS_HPRT (rw) register accessor: OTG_FS host port control and status register (OTG_FS_HPRT)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hprt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hprt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hprt`]
module"]
#[doc(alias = "FS_HPRT")]
pub type FsHprt = crate::Reg<fs_hprt::FsHprtSpec>;
#[doc = "OTG_FS host port control and status register (OTG_FS_HPRT)"]
pub mod fs_hprt;
#[doc = "FS_HCCHAR0 (rw) register accessor: OTG_FS host channel-0 characteristics register (OTG_FS_HCCHAR0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar0`]
module"]
#[doc(alias = "FS_HCCHAR0")]
pub type FsHcchar0 = crate::Reg<fs_hcchar0::FsHcchar0Spec>;
#[doc = "OTG_FS host channel-0 characteristics register (OTG_FS_HCCHAR0)"]
pub mod fs_hcchar0;
#[doc = "FS_HCCHAR1 (rw) register accessor: OTG_FS host channel-1 characteristics register (OTG_FS_HCCHAR1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar1`]
module"]
#[doc(alias = "FS_HCCHAR1")]
pub type FsHcchar1 = crate::Reg<fs_hcchar1::FsHcchar1Spec>;
#[doc = "OTG_FS host channel-1 characteristics register (OTG_FS_HCCHAR1)"]
pub mod fs_hcchar1;
#[doc = "FS_HCCHAR2 (rw) register accessor: OTG_FS host channel-2 characteristics register (OTG_FS_HCCHAR2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar2`]
module"]
#[doc(alias = "FS_HCCHAR2")]
pub type FsHcchar2 = crate::Reg<fs_hcchar2::FsHcchar2Spec>;
#[doc = "OTG_FS host channel-2 characteristics register (OTG_FS_HCCHAR2)"]
pub mod fs_hcchar2;
#[doc = "FS_HCCHAR3 (rw) register accessor: OTG_FS host channel-3 characteristics register (OTG_FS_HCCHAR3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar3`]
module"]
#[doc(alias = "FS_HCCHAR3")]
pub type FsHcchar3 = crate::Reg<fs_hcchar3::FsHcchar3Spec>;
#[doc = "OTG_FS host channel-3 characteristics register (OTG_FS_HCCHAR3)"]
pub mod fs_hcchar3;
#[doc = "FS_HCCHAR4 (rw) register accessor: OTG_FS host channel-4 characteristics register (OTG_FS_HCCHAR4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar4`]
module"]
#[doc(alias = "FS_HCCHAR4")]
pub type FsHcchar4 = crate::Reg<fs_hcchar4::FsHcchar4Spec>;
#[doc = "OTG_FS host channel-4 characteristics register (OTG_FS_HCCHAR4)"]
pub mod fs_hcchar4;
#[doc = "FS_HCCHAR5 (rw) register accessor: OTG_FS host channel-5 characteristics register (OTG_FS_HCCHAR5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar5`]
module"]
#[doc(alias = "FS_HCCHAR5")]
pub type FsHcchar5 = crate::Reg<fs_hcchar5::FsHcchar5Spec>;
#[doc = "OTG_FS host channel-5 characteristics register (OTG_FS_HCCHAR5)"]
pub mod fs_hcchar5;
#[doc = "FS_HCCHAR6 (rw) register accessor: OTG_FS host channel-6 characteristics register (OTG_FS_HCCHAR6)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar6`]
module"]
#[doc(alias = "FS_HCCHAR6")]
pub type FsHcchar6 = crate::Reg<fs_hcchar6::FsHcchar6Spec>;
#[doc = "OTG_FS host channel-6 characteristics register (OTG_FS_HCCHAR6)"]
pub mod fs_hcchar6;
#[doc = "FS_HCCHAR7 (rw) register accessor: OTG_FS host channel-7 characteristics register (OTG_FS_HCCHAR7)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcchar7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcchar7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcchar7`]
module"]
#[doc(alias = "FS_HCCHAR7")]
pub type FsHcchar7 = crate::Reg<fs_hcchar7::FsHcchar7Spec>;
#[doc = "OTG_FS host channel-7 characteristics register (OTG_FS_HCCHAR7)"]
pub mod fs_hcchar7;
#[doc = "FS_HCINT0 (rw) register accessor: OTG_FS host channel-0 interrupt register (OTG_FS_HCINT0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint0`]
module"]
#[doc(alias = "FS_HCINT0")]
pub type FsHcint0 = crate::Reg<fs_hcint0::FsHcint0Spec>;
#[doc = "OTG_FS host channel-0 interrupt register (OTG_FS_HCINT0)"]
pub mod fs_hcint0;
#[doc = "FS_HCINT1 (rw) register accessor: OTG_FS host channel-1 interrupt register (OTG_FS_HCINT1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint1`]
module"]
#[doc(alias = "FS_HCINT1")]
pub type FsHcint1 = crate::Reg<fs_hcint1::FsHcint1Spec>;
#[doc = "OTG_FS host channel-1 interrupt register (OTG_FS_HCINT1)"]
pub mod fs_hcint1;
#[doc = "FS_HCINT2 (rw) register accessor: OTG_FS host channel-2 interrupt register (OTG_FS_HCINT2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint2`]
module"]
#[doc(alias = "FS_HCINT2")]
pub type FsHcint2 = crate::Reg<fs_hcint2::FsHcint2Spec>;
#[doc = "OTG_FS host channel-2 interrupt register (OTG_FS_HCINT2)"]
pub mod fs_hcint2;
#[doc = "FS_HCINT3 (rw) register accessor: OTG_FS host channel-3 interrupt register (OTG_FS_HCINT3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint3`]
module"]
#[doc(alias = "FS_HCINT3")]
pub type FsHcint3 = crate::Reg<fs_hcint3::FsHcint3Spec>;
#[doc = "OTG_FS host channel-3 interrupt register (OTG_FS_HCINT3)"]
pub mod fs_hcint3;
#[doc = "FS_HCINT4 (rw) register accessor: OTG_FS host channel-4 interrupt register (OTG_FS_HCINT4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint4`]
module"]
#[doc(alias = "FS_HCINT4")]
pub type FsHcint4 = crate::Reg<fs_hcint4::FsHcint4Spec>;
#[doc = "OTG_FS host channel-4 interrupt register (OTG_FS_HCINT4)"]
pub mod fs_hcint4;
#[doc = "FS_HCINT5 (rw) register accessor: OTG_FS host channel-5 interrupt register (OTG_FS_HCINT5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint5`]
module"]
#[doc(alias = "FS_HCINT5")]
pub type FsHcint5 = crate::Reg<fs_hcint5::FsHcint5Spec>;
#[doc = "OTG_FS host channel-5 interrupt register (OTG_FS_HCINT5)"]
pub mod fs_hcint5;
#[doc = "FS_HCINT6 (rw) register accessor: OTG_FS host channel-6 interrupt register (OTG_FS_HCINT6)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint6`]
module"]
#[doc(alias = "FS_HCINT6")]
pub type FsHcint6 = crate::Reg<fs_hcint6::FsHcint6Spec>;
#[doc = "OTG_FS host channel-6 interrupt register (OTG_FS_HCINT6)"]
pub mod fs_hcint6;
#[doc = "FS_HCINT7 (rw) register accessor: OTG_FS host channel-7 interrupt register (OTG_FS_HCINT7)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcint7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcint7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcint7`]
module"]
#[doc(alias = "FS_HCINT7")]
pub type FsHcint7 = crate::Reg<fs_hcint7::FsHcint7Spec>;
#[doc = "OTG_FS host channel-7 interrupt register (OTG_FS_HCINT7)"]
pub mod fs_hcint7;
#[doc = "FS_HCINTMSK0 (rw) register accessor: OTG_FS host channel-0 mask register (OTG_FS_HCINTMSK0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk0`]
module"]
#[doc(alias = "FS_HCINTMSK0")]
pub type FsHcintmsk0 = crate::Reg<fs_hcintmsk0::FsHcintmsk0Spec>;
#[doc = "OTG_FS host channel-0 mask register (OTG_FS_HCINTMSK0)"]
pub mod fs_hcintmsk0;
#[doc = "FS_HCINTMSK1 (rw) register accessor: OTG_FS host channel-1 mask register (OTG_FS_HCINTMSK1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk1`]
module"]
#[doc(alias = "FS_HCINTMSK1")]
pub type FsHcintmsk1 = crate::Reg<fs_hcintmsk1::FsHcintmsk1Spec>;
#[doc = "OTG_FS host channel-1 mask register (OTG_FS_HCINTMSK1)"]
pub mod fs_hcintmsk1;
#[doc = "FS_HCINTMSK2 (rw) register accessor: OTG_FS host channel-2 mask register (OTG_FS_HCINTMSK2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk2`]
module"]
#[doc(alias = "FS_HCINTMSK2")]
pub type FsHcintmsk2 = crate::Reg<fs_hcintmsk2::FsHcintmsk2Spec>;
#[doc = "OTG_FS host channel-2 mask register (OTG_FS_HCINTMSK2)"]
pub mod fs_hcintmsk2;
#[doc = "FS_HCINTMSK3 (rw) register accessor: OTG_FS host channel-3 mask register (OTG_FS_HCINTMSK3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk3`]
module"]
#[doc(alias = "FS_HCINTMSK3")]
pub type FsHcintmsk3 = crate::Reg<fs_hcintmsk3::FsHcintmsk3Spec>;
#[doc = "OTG_FS host channel-3 mask register (OTG_FS_HCINTMSK3)"]
pub mod fs_hcintmsk3;
#[doc = "FS_HCINTMSK4 (rw) register accessor: OTG_FS host channel-4 mask register (OTG_FS_HCINTMSK4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk4`]
module"]
#[doc(alias = "FS_HCINTMSK4")]
pub type FsHcintmsk4 = crate::Reg<fs_hcintmsk4::FsHcintmsk4Spec>;
#[doc = "OTG_FS host channel-4 mask register (OTG_FS_HCINTMSK4)"]
pub mod fs_hcintmsk4;
#[doc = "FS_HCINTMSK5 (rw) register accessor: OTG_FS host channel-5 mask register (OTG_FS_HCINTMSK5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk5`]
module"]
#[doc(alias = "FS_HCINTMSK5")]
pub type FsHcintmsk5 = crate::Reg<fs_hcintmsk5::FsHcintmsk5Spec>;
#[doc = "OTG_FS host channel-5 mask register (OTG_FS_HCINTMSK5)"]
pub mod fs_hcintmsk5;
#[doc = "FS_HCINTMSK6 (rw) register accessor: OTG_FS host channel-6 mask register (OTG_FS_HCINTMSK6)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk6`]
module"]
#[doc(alias = "FS_HCINTMSK6")]
pub type FsHcintmsk6 = crate::Reg<fs_hcintmsk6::FsHcintmsk6Spec>;
#[doc = "OTG_FS host channel-6 mask register (OTG_FS_HCINTMSK6)"]
pub mod fs_hcintmsk6;
#[doc = "FS_HCINTMSK7 (rw) register accessor: OTG_FS host channel-7 mask register (OTG_FS_HCINTMSK7)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hcintmsk7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hcintmsk7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hcintmsk7`]
module"]
#[doc(alias = "FS_HCINTMSK7")]
pub type FsHcintmsk7 = crate::Reg<fs_hcintmsk7::FsHcintmsk7Spec>;
#[doc = "OTG_FS host channel-7 mask register (OTG_FS_HCINTMSK7)"]
pub mod fs_hcintmsk7;
#[doc = "FS_HCTSIZ0 (rw) register accessor: OTG_FS host channel-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz0`]
module"]
#[doc(alias = "FS_HCTSIZ0")]
pub type FsHctsiz0 = crate::Reg<fs_hctsiz0::FsHctsiz0Spec>;
#[doc = "OTG_FS host channel-0 transfer size register"]
pub mod fs_hctsiz0;
#[doc = "FS_HCTSIZ1 (rw) register accessor: OTG_FS host channel-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz1`]
module"]
#[doc(alias = "FS_HCTSIZ1")]
pub type FsHctsiz1 = crate::Reg<fs_hctsiz1::FsHctsiz1Spec>;
#[doc = "OTG_FS host channel-1 transfer size register"]
pub mod fs_hctsiz1;
#[doc = "FS_HCTSIZ2 (rw) register accessor: OTG_FS host channel-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz2`]
module"]
#[doc(alias = "FS_HCTSIZ2")]
pub type FsHctsiz2 = crate::Reg<fs_hctsiz2::FsHctsiz2Spec>;
#[doc = "OTG_FS host channel-2 transfer size register"]
pub mod fs_hctsiz2;
#[doc = "FS_HCTSIZ3 (rw) register accessor: OTG_FS host channel-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz3`]
module"]
#[doc(alias = "FS_HCTSIZ3")]
pub type FsHctsiz3 = crate::Reg<fs_hctsiz3::FsHctsiz3Spec>;
#[doc = "OTG_FS host channel-3 transfer size register"]
pub mod fs_hctsiz3;
#[doc = "FS_HCTSIZ4 (rw) register accessor: OTG_FS host channel-x transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz4`]
module"]
#[doc(alias = "FS_HCTSIZ4")]
pub type FsHctsiz4 = crate::Reg<fs_hctsiz4::FsHctsiz4Spec>;
#[doc = "OTG_FS host channel-x transfer size register"]
pub mod fs_hctsiz4;
#[doc = "FS_HCTSIZ5 (rw) register accessor: OTG_FS host channel-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz5`]
module"]
#[doc(alias = "FS_HCTSIZ5")]
pub type FsHctsiz5 = crate::Reg<fs_hctsiz5::FsHctsiz5Spec>;
#[doc = "OTG_FS host channel-5 transfer size register"]
pub mod fs_hctsiz5;
#[doc = "FS_HCTSIZ6 (rw) register accessor: OTG_FS host channel-6 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz6`]
module"]
#[doc(alias = "FS_HCTSIZ6")]
pub type FsHctsiz6 = crate::Reg<fs_hctsiz6::FsHctsiz6Spec>;
#[doc = "OTG_FS host channel-6 transfer size register"]
pub mod fs_hctsiz6;
#[doc = "FS_HCTSIZ7 (rw) register accessor: OTG_FS host channel-7 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fs_hctsiz7`]
module"]
#[doc(alias = "FS_HCTSIZ7")]
pub type FsHctsiz7 = crate::Reg<fs_hctsiz7::FsHctsiz7Spec>;
#[doc = "OTG_FS host channel-7 transfer size register"]
pub mod fs_hctsiz7;
