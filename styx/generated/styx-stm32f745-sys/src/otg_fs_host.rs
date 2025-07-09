// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    otg_fs_hcfg: OtgFsHcfg,
    otg_fs_hfir: OtgFsHfir,
    otg_fs_hfnum: OtgFsHfnum,
    _reserved3: [u8; 0x04],
    otg_fs_hptxsts: OtgFsHptxsts,
    otg_fs_haint: OtgFsHaint,
    otg_fs_haintmsk: OtgFsHaintmsk,
    _reserved6: [u8; 0x24],
    otg_fs_hprt: OtgFsHprt,
    _reserved7: [u8; 0xbc],
    otg_fs_hcchar0: OtgFsHcchar0,
    _reserved8: [u8; 0x04],
    otg_fs_hcint0: OtgFsHcint0,
    otg_fs_hcintmsk0: OtgFsHcintmsk0,
    otg_fs_hctsiz0: OtgFsHctsiz0,
    _reserved11: [u8; 0x0c],
    otg_fs_hcchar1: OtgFsHcchar1,
    _reserved12: [u8; 0x04],
    otg_fs_hcint1: OtgFsHcint1,
    otg_fs_hcintmsk1: OtgFsHcintmsk1,
    otg_fs_hctsiz1: OtgFsHctsiz1,
    _reserved15: [u8; 0x0c],
    otg_fs_hcchar2: OtgFsHcchar2,
    _reserved16: [u8; 0x04],
    otg_fs_hcint2: OtgFsHcint2,
    otg_fs_hcintmsk2: OtgFsHcintmsk2,
    otg_fs_hctsiz2: OtgFsHctsiz2,
    _reserved19: [u8; 0x0c],
    otg_fs_hcchar3: OtgFsHcchar3,
    _reserved20: [u8; 0x04],
    otg_fs_hcint3: OtgFsHcint3,
    otg_fs_hcintmsk3: OtgFsHcintmsk3,
    otg_fs_hctsiz3: OtgFsHctsiz3,
    _reserved23: [u8; 0x0c],
    otg_fs_hcchar4: OtgFsHcchar4,
    _reserved24: [u8; 0x04],
    otg_fs_hcint4: OtgFsHcint4,
    otg_fs_hcintmsk4: OtgFsHcintmsk4,
    otg_fs_hctsiz4: OtgFsHctsiz4,
    _reserved27: [u8; 0x0c],
    otg_fs_hcchar5: OtgFsHcchar5,
    _reserved28: [u8; 0x04],
    otg_fs_hcint5: OtgFsHcint5,
    otg_fs_hcintmsk5: OtgFsHcintmsk5,
    otg_fs_hctsiz5: OtgFsHctsiz5,
    _reserved31: [u8; 0x0c],
    otg_fs_hcchar6: OtgFsHcchar6,
    _reserved32: [u8; 0x04],
    otg_fs_hcint6: OtgFsHcint6,
    otg_fs_hcintmsk6: OtgFsHcintmsk6,
    otg_fs_hctsiz6: OtgFsHctsiz6,
    _reserved35: [u8; 0x0c],
    otg_fs_hcchar7: OtgFsHcchar7,
    _reserved36: [u8; 0x04],
    otg_fs_hcint7: OtgFsHcint7,
    otg_fs_hcintmsk7: OtgFsHcintmsk7,
    otg_fs_hctsiz7: OtgFsHctsiz7,
    otg_fs_hcchar8: OtgFsHcchar8,
    otg_fs_hcint8: OtgFsHcint8,
    otg_fs_hcintmsk8: OtgFsHcintmsk8,
    otg_fs_hctsiz8: OtgFsHctsiz8,
    otg_fs_hcchar9: OtgFsHcchar9,
    otg_fs_hcint9: OtgFsHcint9,
    otg_fs_hcintmsk9: OtgFsHcintmsk9,
    otg_fs_hctsiz9: OtgFsHctsiz9,
    otg_fs_hcchar10: OtgFsHcchar10,
    otg_fs_hcint10: OtgFsHcint10,
    otg_fs_hcintmsk10: OtgFsHcintmsk10,
    otg_fs_hctsiz10: OtgFsHctsiz10,
    otg_fs_hcchar11: OtgFsHcchar11,
    otg_fs_hcint11: OtgFsHcint11,
    otg_fs_hcintmsk11: OtgFsHcintmsk11,
    otg_fs_hctsiz11: OtgFsHctsiz11,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_FS host configuration register (OTG_FS_HCFG)"]
    #[inline(always)]
    pub const fn otg_fs_hcfg(&self) -> &OtgFsHcfg {
        &self.otg_fs_hcfg
    }
    #[doc = "0x04 - OTG_FS Host frame interval register"]
    #[inline(always)]
    pub const fn otg_fs_hfir(&self) -> &OtgFsHfir {
        &self.otg_fs_hfir
    }
    #[doc = "0x08 - OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)"]
    #[inline(always)]
    pub const fn otg_fs_hfnum(&self) -> &OtgFsHfnum {
        &self.otg_fs_hfnum
    }
    #[doc = "0x10 - OTG_FS_Host periodic transmit FIFO/queue status register (OTG_FS_HPTXSTS)"]
    #[inline(always)]
    pub const fn otg_fs_hptxsts(&self) -> &OtgFsHptxsts {
        &self.otg_fs_hptxsts
    }
    #[doc = "0x14 - OTG_FS Host all channels interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_haint(&self) -> &OtgFsHaint {
        &self.otg_fs_haint
    }
    #[doc = "0x18 - OTG_FS host all channels interrupt mask register"]
    #[inline(always)]
    pub const fn otg_fs_haintmsk(&self) -> &OtgFsHaintmsk {
        &self.otg_fs_haintmsk
    }
    #[doc = "0x40 - OTG_FS host port control and status register (OTG_FS_HPRT)"]
    #[inline(always)]
    pub const fn otg_fs_hprt(&self) -> &OtgFsHprt {
        &self.otg_fs_hprt
    }
    #[doc = "0x100 - OTG_FS host channel-0 characteristics register (OTG_FS_HCCHAR0)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar0(&self) -> &OtgFsHcchar0 {
        &self.otg_fs_hcchar0
    }
    #[doc = "0x108 - OTG_FS host channel-0 interrupt register (OTG_FS_HCINT0)"]
    #[inline(always)]
    pub const fn otg_fs_hcint0(&self) -> &OtgFsHcint0 {
        &self.otg_fs_hcint0
    }
    #[doc = "0x10c - OTG_FS host channel-0 mask register (OTG_FS_HCINTMSK0)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk0(&self) -> &OtgFsHcintmsk0 {
        &self.otg_fs_hcintmsk0
    }
    #[doc = "0x110 - OTG_FS host channel-0 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz0(&self) -> &OtgFsHctsiz0 {
        &self.otg_fs_hctsiz0
    }
    #[doc = "0x120 - OTG_FS host channel-1 characteristics register (OTG_FS_HCCHAR1)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar1(&self) -> &OtgFsHcchar1 {
        &self.otg_fs_hcchar1
    }
    #[doc = "0x128 - OTG_FS host channel-1 interrupt register (OTG_FS_HCINT1)"]
    #[inline(always)]
    pub const fn otg_fs_hcint1(&self) -> &OtgFsHcint1 {
        &self.otg_fs_hcint1
    }
    #[doc = "0x12c - OTG_FS host channel-1 mask register (OTG_FS_HCINTMSK1)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk1(&self) -> &OtgFsHcintmsk1 {
        &self.otg_fs_hcintmsk1
    }
    #[doc = "0x130 - OTG_FS host channel-1 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz1(&self) -> &OtgFsHctsiz1 {
        &self.otg_fs_hctsiz1
    }
    #[doc = "0x140 - OTG_FS host channel-2 characteristics register (OTG_FS_HCCHAR2)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar2(&self) -> &OtgFsHcchar2 {
        &self.otg_fs_hcchar2
    }
    #[doc = "0x148 - OTG_FS host channel-2 interrupt register (OTG_FS_HCINT2)"]
    #[inline(always)]
    pub const fn otg_fs_hcint2(&self) -> &OtgFsHcint2 {
        &self.otg_fs_hcint2
    }
    #[doc = "0x14c - OTG_FS host channel-2 mask register (OTG_FS_HCINTMSK2)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk2(&self) -> &OtgFsHcintmsk2 {
        &self.otg_fs_hcintmsk2
    }
    #[doc = "0x150 - OTG_FS host channel-2 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz2(&self) -> &OtgFsHctsiz2 {
        &self.otg_fs_hctsiz2
    }
    #[doc = "0x160 - OTG_FS host channel-3 characteristics register (OTG_FS_HCCHAR3)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar3(&self) -> &OtgFsHcchar3 {
        &self.otg_fs_hcchar3
    }
    #[doc = "0x168 - OTG_FS host channel-3 interrupt register (OTG_FS_HCINT3)"]
    #[inline(always)]
    pub const fn otg_fs_hcint3(&self) -> &OtgFsHcint3 {
        &self.otg_fs_hcint3
    }
    #[doc = "0x16c - OTG_FS host channel-3 mask register (OTG_FS_HCINTMSK3)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk3(&self) -> &OtgFsHcintmsk3 {
        &self.otg_fs_hcintmsk3
    }
    #[doc = "0x170 - OTG_FS host channel-3 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz3(&self) -> &OtgFsHctsiz3 {
        &self.otg_fs_hctsiz3
    }
    #[doc = "0x180 - OTG_FS host channel-4 characteristics register (OTG_FS_HCCHAR4)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar4(&self) -> &OtgFsHcchar4 {
        &self.otg_fs_hcchar4
    }
    #[doc = "0x188 - OTG_FS host channel-4 interrupt register (OTG_FS_HCINT4)"]
    #[inline(always)]
    pub const fn otg_fs_hcint4(&self) -> &OtgFsHcint4 {
        &self.otg_fs_hcint4
    }
    #[doc = "0x18c - OTG_FS host channel-4 mask register (OTG_FS_HCINTMSK4)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk4(&self) -> &OtgFsHcintmsk4 {
        &self.otg_fs_hcintmsk4
    }
    #[doc = "0x190 - OTG_FS host channel-x transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz4(&self) -> &OtgFsHctsiz4 {
        &self.otg_fs_hctsiz4
    }
    #[doc = "0x1a0 - OTG_FS host channel-5 characteristics register (OTG_FS_HCCHAR5)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar5(&self) -> &OtgFsHcchar5 {
        &self.otg_fs_hcchar5
    }
    #[doc = "0x1a8 - OTG_FS host channel-5 interrupt register (OTG_FS_HCINT5)"]
    #[inline(always)]
    pub const fn otg_fs_hcint5(&self) -> &OtgFsHcint5 {
        &self.otg_fs_hcint5
    }
    #[doc = "0x1ac - OTG_FS host channel-5 mask register (OTG_FS_HCINTMSK5)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk5(&self) -> &OtgFsHcintmsk5 {
        &self.otg_fs_hcintmsk5
    }
    #[doc = "0x1b0 - OTG_FS host channel-5 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz5(&self) -> &OtgFsHctsiz5 {
        &self.otg_fs_hctsiz5
    }
    #[doc = "0x1c0 - OTG_FS host channel-6 characteristics register (OTG_FS_HCCHAR6)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar6(&self) -> &OtgFsHcchar6 {
        &self.otg_fs_hcchar6
    }
    #[doc = "0x1c8 - OTG_FS host channel-6 interrupt register (OTG_FS_HCINT6)"]
    #[inline(always)]
    pub const fn otg_fs_hcint6(&self) -> &OtgFsHcint6 {
        &self.otg_fs_hcint6
    }
    #[doc = "0x1cc - OTG_FS host channel-6 mask register (OTG_FS_HCINTMSK6)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk6(&self) -> &OtgFsHcintmsk6 {
        &self.otg_fs_hcintmsk6
    }
    #[doc = "0x1d0 - OTG_FS host channel-6 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz6(&self) -> &OtgFsHctsiz6 {
        &self.otg_fs_hctsiz6
    }
    #[doc = "0x1e0 - OTG_FS host channel-7 characteristics register (OTG_FS_HCCHAR7)"]
    #[inline(always)]
    pub const fn otg_fs_hcchar7(&self) -> &OtgFsHcchar7 {
        &self.otg_fs_hcchar7
    }
    #[doc = "0x1e8 - OTG_FS host channel-7 interrupt register (OTG_FS_HCINT7)"]
    #[inline(always)]
    pub const fn otg_fs_hcint7(&self) -> &OtgFsHcint7 {
        &self.otg_fs_hcint7
    }
    #[doc = "0x1ec - OTG_FS host channel-7 mask register (OTG_FS_HCINTMSK7)"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk7(&self) -> &OtgFsHcintmsk7 {
        &self.otg_fs_hcintmsk7
    }
    #[doc = "0x1f0 - OTG_FS host channel-7 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz7(&self) -> &OtgFsHctsiz7 {
        &self.otg_fs_hctsiz7
    }
    #[doc = "0x1f4 - OTG_FS host channel-8 characteristics register"]
    #[inline(always)]
    pub const fn otg_fs_hcchar8(&self) -> &OtgFsHcchar8 {
        &self.otg_fs_hcchar8
    }
    #[doc = "0x1f8 - OTG_FS host channel-8 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_hcint8(&self) -> &OtgFsHcint8 {
        &self.otg_fs_hcint8
    }
    #[doc = "0x1fc - OTG_FS host channel-8 mask register"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk8(&self) -> &OtgFsHcintmsk8 {
        &self.otg_fs_hcintmsk8
    }
    #[doc = "0x200 - OTG_FS host channel-8 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz8(&self) -> &OtgFsHctsiz8 {
        &self.otg_fs_hctsiz8
    }
    #[doc = "0x204 - OTG_FS host channel-9 characteristics register"]
    #[inline(always)]
    pub const fn otg_fs_hcchar9(&self) -> &OtgFsHcchar9 {
        &self.otg_fs_hcchar9
    }
    #[doc = "0x208 - OTG_FS host channel-9 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_hcint9(&self) -> &OtgFsHcint9 {
        &self.otg_fs_hcint9
    }
    #[doc = "0x20c - OTG_FS host channel-9 mask register"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk9(&self) -> &OtgFsHcintmsk9 {
        &self.otg_fs_hcintmsk9
    }
    #[doc = "0x210 - OTG_FS host channel-9 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz9(&self) -> &OtgFsHctsiz9 {
        &self.otg_fs_hctsiz9
    }
    #[doc = "0x214 - OTG_FS host channel-10 characteristics register"]
    #[inline(always)]
    pub const fn otg_fs_hcchar10(&self) -> &OtgFsHcchar10 {
        &self.otg_fs_hcchar10
    }
    #[doc = "0x218 - OTG_FS host channel-10 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_hcint10(&self) -> &OtgFsHcint10 {
        &self.otg_fs_hcint10
    }
    #[doc = "0x21c - OTG_FS host channel-10 mask register"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk10(&self) -> &OtgFsHcintmsk10 {
        &self.otg_fs_hcintmsk10
    }
    #[doc = "0x220 - OTG_FS host channel-10 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz10(&self) -> &OtgFsHctsiz10 {
        &self.otg_fs_hctsiz10
    }
    #[doc = "0x224 - OTG_FS host channel-11 characteristics register"]
    #[inline(always)]
    pub const fn otg_fs_hcchar11(&self) -> &OtgFsHcchar11 {
        &self.otg_fs_hcchar11
    }
    #[doc = "0x228 - OTG_FS host channel-11 interrupt register"]
    #[inline(always)]
    pub const fn otg_fs_hcint11(&self) -> &OtgFsHcint11 {
        &self.otg_fs_hcint11
    }
    #[doc = "0x22c - OTG_FS host channel-11 mask register"]
    #[inline(always)]
    pub const fn otg_fs_hcintmsk11(&self) -> &OtgFsHcintmsk11 {
        &self.otg_fs_hcintmsk11
    }
    #[doc = "0x230 - OTG_FS host channel-11 transfer size register"]
    #[inline(always)]
    pub const fn otg_fs_hctsiz11(&self) -> &OtgFsHctsiz11 {
        &self.otg_fs_hctsiz11
    }
}
#[doc = "OTG_FS_HCFG (rw) register accessor: OTG_FS host configuration register (OTG_FS_HCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcfg`]
module"]
#[doc(alias = "OTG_FS_HCFG")]
pub type OtgFsHcfg = crate::Reg<otg_fs_hcfg::OtgFsHcfgSpec>;
#[doc = "OTG_FS host configuration register (OTG_FS_HCFG)"]
pub mod otg_fs_hcfg;
#[doc = "OTG_FS_HFIR (rw) register accessor: OTG_FS Host frame interval register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hfir::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hfir::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hfir`]
module"]
#[doc(alias = "OTG_FS_HFIR")]
pub type OtgFsHfir = crate::Reg<otg_fs_hfir::OtgFsHfirSpec>;
#[doc = "OTG_FS Host frame interval register"]
pub mod otg_fs_hfir;
#[doc = "OTG_FS_HFNUM (r) register accessor: OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hfnum::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hfnum`]
module"]
#[doc(alias = "OTG_FS_HFNUM")]
pub type OtgFsHfnum = crate::Reg<otg_fs_hfnum::OtgFsHfnumSpec>;
#[doc = "OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)"]
pub mod otg_fs_hfnum;
#[doc = "OTG_FS_HPTXSTS (rw) register accessor: OTG_FS_Host periodic transmit FIFO/queue status register (OTG_FS_HPTXSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hptxsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hptxsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hptxsts`]
module"]
#[doc(alias = "OTG_FS_HPTXSTS")]
pub type OtgFsHptxsts = crate::Reg<otg_fs_hptxsts::OtgFsHptxstsSpec>;
#[doc = "OTG_FS_Host periodic transmit FIFO/queue status register (OTG_FS_HPTXSTS)"]
pub mod otg_fs_hptxsts;
#[doc = "OTG_FS_HAINT (r) register accessor: OTG_FS Host all channels interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_haint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_haint`]
module"]
#[doc(alias = "OTG_FS_HAINT")]
pub type OtgFsHaint = crate::Reg<otg_fs_haint::OtgFsHaintSpec>;
#[doc = "OTG_FS Host all channels interrupt register"]
pub mod otg_fs_haint;
#[doc = "OTG_FS_HAINTMSK (rw) register accessor: OTG_FS host all channels interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_haintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_haintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_haintmsk`]
module"]
#[doc(alias = "OTG_FS_HAINTMSK")]
pub type OtgFsHaintmsk = crate::Reg<otg_fs_haintmsk::OtgFsHaintmskSpec>;
#[doc = "OTG_FS host all channels interrupt mask register"]
pub mod otg_fs_haintmsk;
#[doc = "OTG_FS_HPRT (rw) register accessor: OTG_FS host port control and status register (OTG_FS_HPRT)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hprt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hprt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hprt`]
module"]
#[doc(alias = "OTG_FS_HPRT")]
pub type OtgFsHprt = crate::Reg<otg_fs_hprt::OtgFsHprtSpec>;
#[doc = "OTG_FS host port control and status register (OTG_FS_HPRT)"]
pub mod otg_fs_hprt;
#[doc = "OTG_FS_HCCHAR0 (rw) register accessor: OTG_FS host channel-0 characteristics register (OTG_FS_HCCHAR0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar0`]
module"]
#[doc(alias = "OTG_FS_HCCHAR0")]
pub type OtgFsHcchar0 = crate::Reg<otg_fs_hcchar0::OtgFsHcchar0Spec>;
#[doc = "OTG_FS host channel-0 characteristics register (OTG_FS_HCCHAR0)"]
pub mod otg_fs_hcchar0;
#[doc = "OTG_FS_HCCHAR1 (rw) register accessor: OTG_FS host channel-1 characteristics register (OTG_FS_HCCHAR1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar1`]
module"]
#[doc(alias = "OTG_FS_HCCHAR1")]
pub type OtgFsHcchar1 = crate::Reg<otg_fs_hcchar1::OtgFsHcchar1Spec>;
#[doc = "OTG_FS host channel-1 characteristics register (OTG_FS_HCCHAR1)"]
pub mod otg_fs_hcchar1;
#[doc = "OTG_FS_HCCHAR2 (rw) register accessor: OTG_FS host channel-2 characteristics register (OTG_FS_HCCHAR2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar2`]
module"]
#[doc(alias = "OTG_FS_HCCHAR2")]
pub type OtgFsHcchar2 = crate::Reg<otg_fs_hcchar2::OtgFsHcchar2Spec>;
#[doc = "OTG_FS host channel-2 characteristics register (OTG_FS_HCCHAR2)"]
pub mod otg_fs_hcchar2;
#[doc = "OTG_FS_HCCHAR3 (rw) register accessor: OTG_FS host channel-3 characteristics register (OTG_FS_HCCHAR3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar3`]
module"]
#[doc(alias = "OTG_FS_HCCHAR3")]
pub type OtgFsHcchar3 = crate::Reg<otg_fs_hcchar3::OtgFsHcchar3Spec>;
#[doc = "OTG_FS host channel-3 characteristics register (OTG_FS_HCCHAR3)"]
pub mod otg_fs_hcchar3;
#[doc = "OTG_FS_HCCHAR4 (rw) register accessor: OTG_FS host channel-4 characteristics register (OTG_FS_HCCHAR4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar4`]
module"]
#[doc(alias = "OTG_FS_HCCHAR4")]
pub type OtgFsHcchar4 = crate::Reg<otg_fs_hcchar4::OtgFsHcchar4Spec>;
#[doc = "OTG_FS host channel-4 characteristics register (OTG_FS_HCCHAR4)"]
pub mod otg_fs_hcchar4;
#[doc = "OTG_FS_HCCHAR5 (rw) register accessor: OTG_FS host channel-5 characteristics register (OTG_FS_HCCHAR5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar5`]
module"]
#[doc(alias = "OTG_FS_HCCHAR5")]
pub type OtgFsHcchar5 = crate::Reg<otg_fs_hcchar5::OtgFsHcchar5Spec>;
#[doc = "OTG_FS host channel-5 characteristics register (OTG_FS_HCCHAR5)"]
pub mod otg_fs_hcchar5;
#[doc = "OTG_FS_HCCHAR6 (rw) register accessor: OTG_FS host channel-6 characteristics register (OTG_FS_HCCHAR6)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar6`]
module"]
#[doc(alias = "OTG_FS_HCCHAR6")]
pub type OtgFsHcchar6 = crate::Reg<otg_fs_hcchar6::OtgFsHcchar6Spec>;
#[doc = "OTG_FS host channel-6 characteristics register (OTG_FS_HCCHAR6)"]
pub mod otg_fs_hcchar6;
#[doc = "OTG_FS_HCCHAR7 (rw) register accessor: OTG_FS host channel-7 characteristics register (OTG_FS_HCCHAR7)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar7`]
module"]
#[doc(alias = "OTG_FS_HCCHAR7")]
pub type OtgFsHcchar7 = crate::Reg<otg_fs_hcchar7::OtgFsHcchar7Spec>;
#[doc = "OTG_FS host channel-7 characteristics register (OTG_FS_HCCHAR7)"]
pub mod otg_fs_hcchar7;
#[doc = "OTG_FS_HCINT0 (rw) register accessor: OTG_FS host channel-0 interrupt register (OTG_FS_HCINT0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint0`]
module"]
#[doc(alias = "OTG_FS_HCINT0")]
pub type OtgFsHcint0 = crate::Reg<otg_fs_hcint0::OtgFsHcint0Spec>;
#[doc = "OTG_FS host channel-0 interrupt register (OTG_FS_HCINT0)"]
pub mod otg_fs_hcint0;
#[doc = "OTG_FS_HCINT1 (rw) register accessor: OTG_FS host channel-1 interrupt register (OTG_FS_HCINT1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint1`]
module"]
#[doc(alias = "OTG_FS_HCINT1")]
pub type OtgFsHcint1 = crate::Reg<otg_fs_hcint1::OtgFsHcint1Spec>;
#[doc = "OTG_FS host channel-1 interrupt register (OTG_FS_HCINT1)"]
pub mod otg_fs_hcint1;
#[doc = "OTG_FS_HCINT2 (rw) register accessor: OTG_FS host channel-2 interrupt register (OTG_FS_HCINT2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint2`]
module"]
#[doc(alias = "OTG_FS_HCINT2")]
pub type OtgFsHcint2 = crate::Reg<otg_fs_hcint2::OtgFsHcint2Spec>;
#[doc = "OTG_FS host channel-2 interrupt register (OTG_FS_HCINT2)"]
pub mod otg_fs_hcint2;
#[doc = "OTG_FS_HCINT3 (rw) register accessor: OTG_FS host channel-3 interrupt register (OTG_FS_HCINT3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint3`]
module"]
#[doc(alias = "OTG_FS_HCINT3")]
pub type OtgFsHcint3 = crate::Reg<otg_fs_hcint3::OtgFsHcint3Spec>;
#[doc = "OTG_FS host channel-3 interrupt register (OTG_FS_HCINT3)"]
pub mod otg_fs_hcint3;
#[doc = "OTG_FS_HCINT4 (rw) register accessor: OTG_FS host channel-4 interrupt register (OTG_FS_HCINT4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint4`]
module"]
#[doc(alias = "OTG_FS_HCINT4")]
pub type OtgFsHcint4 = crate::Reg<otg_fs_hcint4::OtgFsHcint4Spec>;
#[doc = "OTG_FS host channel-4 interrupt register (OTG_FS_HCINT4)"]
pub mod otg_fs_hcint4;
#[doc = "OTG_FS_HCINT5 (rw) register accessor: OTG_FS host channel-5 interrupt register (OTG_FS_HCINT5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint5`]
module"]
#[doc(alias = "OTG_FS_HCINT5")]
pub type OtgFsHcint5 = crate::Reg<otg_fs_hcint5::OtgFsHcint5Spec>;
#[doc = "OTG_FS host channel-5 interrupt register (OTG_FS_HCINT5)"]
pub mod otg_fs_hcint5;
#[doc = "OTG_FS_HCINT6 (rw) register accessor: OTG_FS host channel-6 interrupt register (OTG_FS_HCINT6)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint6`]
module"]
#[doc(alias = "OTG_FS_HCINT6")]
pub type OtgFsHcint6 = crate::Reg<otg_fs_hcint6::OtgFsHcint6Spec>;
#[doc = "OTG_FS host channel-6 interrupt register (OTG_FS_HCINT6)"]
pub mod otg_fs_hcint6;
#[doc = "OTG_FS_HCINT7 (rw) register accessor: OTG_FS host channel-7 interrupt register (OTG_FS_HCINT7)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint7`]
module"]
#[doc(alias = "OTG_FS_HCINT7")]
pub type OtgFsHcint7 = crate::Reg<otg_fs_hcint7::OtgFsHcint7Spec>;
#[doc = "OTG_FS host channel-7 interrupt register (OTG_FS_HCINT7)"]
pub mod otg_fs_hcint7;
#[doc = "OTG_FS_HCINTMSK0 (rw) register accessor: OTG_FS host channel-0 mask register (OTG_FS_HCINTMSK0)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk0`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK0")]
pub type OtgFsHcintmsk0 = crate::Reg<otg_fs_hcintmsk0::OtgFsHcintmsk0Spec>;
#[doc = "OTG_FS host channel-0 mask register (OTG_FS_HCINTMSK0)"]
pub mod otg_fs_hcintmsk0;
#[doc = "OTG_FS_HCINTMSK1 (rw) register accessor: OTG_FS host channel-1 mask register (OTG_FS_HCINTMSK1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk1`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK1")]
pub type OtgFsHcintmsk1 = crate::Reg<otg_fs_hcintmsk1::OtgFsHcintmsk1Spec>;
#[doc = "OTG_FS host channel-1 mask register (OTG_FS_HCINTMSK1)"]
pub mod otg_fs_hcintmsk1;
#[doc = "OTG_FS_HCINTMSK2 (rw) register accessor: OTG_FS host channel-2 mask register (OTG_FS_HCINTMSK2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk2`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK2")]
pub type OtgFsHcintmsk2 = crate::Reg<otg_fs_hcintmsk2::OtgFsHcintmsk2Spec>;
#[doc = "OTG_FS host channel-2 mask register (OTG_FS_HCINTMSK2)"]
pub mod otg_fs_hcintmsk2;
#[doc = "OTG_FS_HCINTMSK3 (rw) register accessor: OTG_FS host channel-3 mask register (OTG_FS_HCINTMSK3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk3`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK3")]
pub type OtgFsHcintmsk3 = crate::Reg<otg_fs_hcintmsk3::OtgFsHcintmsk3Spec>;
#[doc = "OTG_FS host channel-3 mask register (OTG_FS_HCINTMSK3)"]
pub mod otg_fs_hcintmsk3;
#[doc = "OTG_FS_HCINTMSK4 (rw) register accessor: OTG_FS host channel-4 mask register (OTG_FS_HCINTMSK4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk4`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK4")]
pub type OtgFsHcintmsk4 = crate::Reg<otg_fs_hcintmsk4::OtgFsHcintmsk4Spec>;
#[doc = "OTG_FS host channel-4 mask register (OTG_FS_HCINTMSK4)"]
pub mod otg_fs_hcintmsk4;
#[doc = "OTG_FS_HCINTMSK5 (rw) register accessor: OTG_FS host channel-5 mask register (OTG_FS_HCINTMSK5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk5`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK5")]
pub type OtgFsHcintmsk5 = crate::Reg<otg_fs_hcintmsk5::OtgFsHcintmsk5Spec>;
#[doc = "OTG_FS host channel-5 mask register (OTG_FS_HCINTMSK5)"]
pub mod otg_fs_hcintmsk5;
#[doc = "OTG_FS_HCINTMSK6 (rw) register accessor: OTG_FS host channel-6 mask register (OTG_FS_HCINTMSK6)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk6`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK6")]
pub type OtgFsHcintmsk6 = crate::Reg<otg_fs_hcintmsk6::OtgFsHcintmsk6Spec>;
#[doc = "OTG_FS host channel-6 mask register (OTG_FS_HCINTMSK6)"]
pub mod otg_fs_hcintmsk6;
#[doc = "OTG_FS_HCINTMSK7 (rw) register accessor: OTG_FS host channel-7 mask register (OTG_FS_HCINTMSK7)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk7`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK7")]
pub type OtgFsHcintmsk7 = crate::Reg<otg_fs_hcintmsk7::OtgFsHcintmsk7Spec>;
#[doc = "OTG_FS host channel-7 mask register (OTG_FS_HCINTMSK7)"]
pub mod otg_fs_hcintmsk7;
#[doc = "OTG_FS_HCTSIZ0 (rw) register accessor: OTG_FS host channel-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz0`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ0")]
pub type OtgFsHctsiz0 = crate::Reg<otg_fs_hctsiz0::OtgFsHctsiz0Spec>;
#[doc = "OTG_FS host channel-0 transfer size register"]
pub mod otg_fs_hctsiz0;
#[doc = "OTG_FS_HCTSIZ1 (rw) register accessor: OTG_FS host channel-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz1`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ1")]
pub type OtgFsHctsiz1 = crate::Reg<otg_fs_hctsiz1::OtgFsHctsiz1Spec>;
#[doc = "OTG_FS host channel-1 transfer size register"]
pub mod otg_fs_hctsiz1;
#[doc = "OTG_FS_HCTSIZ2 (rw) register accessor: OTG_FS host channel-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz2`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ2")]
pub type OtgFsHctsiz2 = crate::Reg<otg_fs_hctsiz2::OtgFsHctsiz2Spec>;
#[doc = "OTG_FS host channel-2 transfer size register"]
pub mod otg_fs_hctsiz2;
#[doc = "OTG_FS_HCTSIZ3 (rw) register accessor: OTG_FS host channel-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz3`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ3")]
pub type OtgFsHctsiz3 = crate::Reg<otg_fs_hctsiz3::OtgFsHctsiz3Spec>;
#[doc = "OTG_FS host channel-3 transfer size register"]
pub mod otg_fs_hctsiz3;
#[doc = "OTG_FS_HCTSIZ4 (rw) register accessor: OTG_FS host channel-x transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz4`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ4")]
pub type OtgFsHctsiz4 = crate::Reg<otg_fs_hctsiz4::OtgFsHctsiz4Spec>;
#[doc = "OTG_FS host channel-x transfer size register"]
pub mod otg_fs_hctsiz4;
#[doc = "OTG_FS_HCTSIZ5 (rw) register accessor: OTG_FS host channel-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz5`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ5")]
pub type OtgFsHctsiz5 = crate::Reg<otg_fs_hctsiz5::OtgFsHctsiz5Spec>;
#[doc = "OTG_FS host channel-5 transfer size register"]
pub mod otg_fs_hctsiz5;
#[doc = "OTG_FS_HCTSIZ6 (rw) register accessor: OTG_FS host channel-6 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz6`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ6")]
pub type OtgFsHctsiz6 = crate::Reg<otg_fs_hctsiz6::OtgFsHctsiz6Spec>;
#[doc = "OTG_FS host channel-6 transfer size register"]
pub mod otg_fs_hctsiz6;
#[doc = "OTG_FS_HCTSIZ7 (rw) register accessor: OTG_FS host channel-7 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz7`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ7")]
pub type OtgFsHctsiz7 = crate::Reg<otg_fs_hctsiz7::OtgFsHctsiz7Spec>;
#[doc = "OTG_FS host channel-7 transfer size register"]
pub mod otg_fs_hctsiz7;
#[doc = "OTG_FS_HCCHAR8 (rw) register accessor: OTG_FS host channel-8 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar8`]
module"]
#[doc(alias = "OTG_FS_HCCHAR8")]
pub type OtgFsHcchar8 = crate::Reg<otg_fs_hcchar8::OtgFsHcchar8Spec>;
#[doc = "OTG_FS host channel-8 characteristics register"]
pub mod otg_fs_hcchar8;
#[doc = "OTG_FS_HCINT8 (rw) register accessor: OTG_FS host channel-8 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint8`]
module"]
#[doc(alias = "OTG_FS_HCINT8")]
pub type OtgFsHcint8 = crate::Reg<otg_fs_hcint8::OtgFsHcint8Spec>;
#[doc = "OTG_FS host channel-8 interrupt register"]
pub mod otg_fs_hcint8;
#[doc = "OTG_FS_HCINTMSK8 (rw) register accessor: OTG_FS host channel-8 mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk8`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK8")]
pub type OtgFsHcintmsk8 = crate::Reg<otg_fs_hcintmsk8::OtgFsHcintmsk8Spec>;
#[doc = "OTG_FS host channel-8 mask register"]
pub mod otg_fs_hcintmsk8;
#[doc = "OTG_FS_HCTSIZ8 (rw) register accessor: OTG_FS host channel-8 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz8`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ8")]
pub type OtgFsHctsiz8 = crate::Reg<otg_fs_hctsiz8::OtgFsHctsiz8Spec>;
#[doc = "OTG_FS host channel-8 transfer size register"]
pub mod otg_fs_hctsiz8;
#[doc = "OTG_FS_HCCHAR9 (rw) register accessor: OTG_FS host channel-9 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar9`]
module"]
#[doc(alias = "OTG_FS_HCCHAR9")]
pub type OtgFsHcchar9 = crate::Reg<otg_fs_hcchar9::OtgFsHcchar9Spec>;
#[doc = "OTG_FS host channel-9 characteristics register"]
pub mod otg_fs_hcchar9;
#[doc = "OTG_FS_HCINT9 (rw) register accessor: OTG_FS host channel-9 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint9`]
module"]
#[doc(alias = "OTG_FS_HCINT9")]
pub type OtgFsHcint9 = crate::Reg<otg_fs_hcint9::OtgFsHcint9Spec>;
#[doc = "OTG_FS host channel-9 interrupt register"]
pub mod otg_fs_hcint9;
#[doc = "OTG_FS_HCINTMSK9 (rw) register accessor: OTG_FS host channel-9 mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk9`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK9")]
pub type OtgFsHcintmsk9 = crate::Reg<otg_fs_hcintmsk9::OtgFsHcintmsk9Spec>;
#[doc = "OTG_FS host channel-9 mask register"]
pub mod otg_fs_hcintmsk9;
#[doc = "OTG_FS_HCTSIZ9 (rw) register accessor: OTG_FS host channel-9 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz9`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ9")]
pub type OtgFsHctsiz9 = crate::Reg<otg_fs_hctsiz9::OtgFsHctsiz9Spec>;
#[doc = "OTG_FS host channel-9 transfer size register"]
pub mod otg_fs_hctsiz9;
#[doc = "OTG_FS_HCCHAR10 (rw) register accessor: OTG_FS host channel-10 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar10`]
module"]
#[doc(alias = "OTG_FS_HCCHAR10")]
pub type OtgFsHcchar10 = crate::Reg<otg_fs_hcchar10::OtgFsHcchar10Spec>;
#[doc = "OTG_FS host channel-10 characteristics register"]
pub mod otg_fs_hcchar10;
#[doc = "OTG_FS_HCINT10 (rw) register accessor: OTG_FS host channel-10 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint10`]
module"]
#[doc(alias = "OTG_FS_HCINT10")]
pub type OtgFsHcint10 = crate::Reg<otg_fs_hcint10::OtgFsHcint10Spec>;
#[doc = "OTG_FS host channel-10 interrupt register"]
pub mod otg_fs_hcint10;
#[doc = "OTG_FS_HCINTMSK10 (rw) register accessor: OTG_FS host channel-10 mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk10`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK10")]
pub type OtgFsHcintmsk10 = crate::Reg<otg_fs_hcintmsk10::OtgFsHcintmsk10Spec>;
#[doc = "OTG_FS host channel-10 mask register"]
pub mod otg_fs_hcintmsk10;
#[doc = "OTG_FS_HCTSIZ10 (rw) register accessor: OTG_FS host channel-10 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz10`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ10")]
pub type OtgFsHctsiz10 = crate::Reg<otg_fs_hctsiz10::OtgFsHctsiz10Spec>;
#[doc = "OTG_FS host channel-10 transfer size register"]
pub mod otg_fs_hctsiz10;
#[doc = "OTG_FS_HCCHAR11 (rw) register accessor: OTG_FS host channel-11 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcchar11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcchar11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcchar11`]
module"]
#[doc(alias = "OTG_FS_HCCHAR11")]
pub type OtgFsHcchar11 = crate::Reg<otg_fs_hcchar11::OtgFsHcchar11Spec>;
#[doc = "OTG_FS host channel-11 characteristics register"]
pub mod otg_fs_hcchar11;
#[doc = "OTG_FS_HCINT11 (rw) register accessor: OTG_FS host channel-11 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcint11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcint11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcint11`]
module"]
#[doc(alias = "OTG_FS_HCINT11")]
pub type OtgFsHcint11 = crate::Reg<otg_fs_hcint11::OtgFsHcint11Spec>;
#[doc = "OTG_FS host channel-11 interrupt register"]
pub mod otg_fs_hcint11;
#[doc = "OTG_FS_HCINTMSK11 (rw) register accessor: OTG_FS host channel-11 mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcintmsk11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcintmsk11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hcintmsk11`]
module"]
#[doc(alias = "OTG_FS_HCINTMSK11")]
pub type OtgFsHcintmsk11 = crate::Reg<otg_fs_hcintmsk11::OtgFsHcintmsk11Spec>;
#[doc = "OTG_FS host channel-11 mask register"]
pub mod otg_fs_hcintmsk11;
#[doc = "OTG_FS_HCTSIZ11 (rw) register accessor: OTG_FS host channel-11 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hctsiz11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hctsiz11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hctsiz11`]
module"]
#[doc(alias = "OTG_FS_HCTSIZ11")]
pub type OtgFsHctsiz11 = crate::Reg<otg_fs_hctsiz11::OtgFsHctsiz11Spec>;
#[doc = "OTG_FS host channel-11 transfer size register"]
pub mod otg_fs_hctsiz11;
