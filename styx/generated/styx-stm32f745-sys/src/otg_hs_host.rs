// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    otg_hs_hcfg: OtgHsHcfg,
    otg_hs_hfir: OtgHsHfir,
    otg_hs_hfnum: OtgHsHfnum,
    _reserved3: [u8; 0x04],
    otg_hs_hptxsts: OtgHsHptxsts,
    otg_hs_haint: OtgHsHaint,
    otg_hs_haintmsk: OtgHsHaintmsk,
    _reserved6: [u8; 0x24],
    otg_hs_hprt: OtgHsHprt,
    _reserved7: [u8; 0xbc],
    otg_hs_hcchar0: OtgHsHcchar0,
    otg_hs_hcsplt0: OtgHsHcsplt0,
    otg_hs_hcint0: OtgHsHcint0,
    otg_hs_hcintmsk0: OtgHsHcintmsk0,
    otg_hs_hctsiz0: OtgHsHctsiz0,
    otg_hs_hcdma0: OtgHsHcdma0,
    _reserved13: [u8; 0x08],
    otg_hs_hcchar1: OtgHsHcchar1,
    otg_hs_hcsplt1: OtgHsHcsplt1,
    otg_hs_hcint1: OtgHsHcint1,
    otg_hs_hcintmsk1: OtgHsHcintmsk1,
    otg_hs_hctsiz1: OtgHsHctsiz1,
    otg_hs_hcdma1: OtgHsHcdma1,
    _reserved19: [u8; 0x08],
    otg_hs_hcchar2: OtgHsHcchar2,
    otg_hs_hcsplt2: OtgHsHcsplt2,
    otg_hs_hcint2: OtgHsHcint2,
    otg_hs_hcintmsk2: OtgHsHcintmsk2,
    otg_hs_hctsiz2: OtgHsHctsiz2,
    otg_hs_hcdma2: OtgHsHcdma2,
    _reserved25: [u8; 0x08],
    otg_hs_hcchar3: OtgHsHcchar3,
    otg_hs_hcsplt3: OtgHsHcsplt3,
    otg_hs_hcint3: OtgHsHcint3,
    otg_hs_hcintmsk3: OtgHsHcintmsk3,
    otg_hs_hctsiz3: OtgHsHctsiz3,
    otg_hs_hcdma3: OtgHsHcdma3,
    _reserved31: [u8; 0x08],
    otg_hs_hcchar4: OtgHsHcchar4,
    otg_hs_hcsplt4: OtgHsHcsplt4,
    otg_hs_hcint4: OtgHsHcint4,
    otg_hs_hcintmsk4: OtgHsHcintmsk4,
    otg_hs_hctsiz4: OtgHsHctsiz4,
    otg_hs_hcdma4: OtgHsHcdma4,
    _reserved37: [u8; 0x08],
    otg_hs_hcchar5: OtgHsHcchar5,
    otg_hs_hcsplt5: OtgHsHcsplt5,
    otg_hs_hcint5: OtgHsHcint5,
    otg_hs_hcintmsk5: OtgHsHcintmsk5,
    otg_hs_hctsiz5: OtgHsHctsiz5,
    otg_hs_hcdma5: OtgHsHcdma5,
    _reserved43: [u8; 0x08],
    otg_hs_hcchar6: OtgHsHcchar6,
    otg_hs_hcsplt6: OtgHsHcsplt6,
    otg_hs_hcint6: OtgHsHcint6,
    otg_hs_hcintmsk6: OtgHsHcintmsk6,
    otg_hs_hctsiz6: OtgHsHctsiz6,
    otg_hs_hcdma6: OtgHsHcdma6,
    _reserved49: [u8; 0x08],
    otg_hs_hcchar7: OtgHsHcchar7,
    otg_hs_hcsplt7: OtgHsHcsplt7,
    otg_hs_hcint7: OtgHsHcint7,
    otg_hs_hcintmsk7: OtgHsHcintmsk7,
    otg_hs_hctsiz7: OtgHsHctsiz7,
    otg_hs_hcdma7: OtgHsHcdma7,
    _reserved55: [u8; 0x08],
    otg_hs_hcchar8: OtgHsHcchar8,
    otg_hs_hcsplt8: OtgHsHcsplt8,
    otg_hs_hcint8: OtgHsHcint8,
    otg_hs_hcintmsk8: OtgHsHcintmsk8,
    otg_hs_hctsiz8: OtgHsHctsiz8,
    otg_hs_hcdma8: OtgHsHcdma8,
    _reserved61: [u8; 0x08],
    otg_hs_hcchar9: OtgHsHcchar9,
    otg_hs_hcsplt9: OtgHsHcsplt9,
    otg_hs_hcint9: OtgHsHcint9,
    otg_hs_hcintmsk9: OtgHsHcintmsk9,
    otg_hs_hctsiz9: OtgHsHctsiz9,
    otg_hs_hcdma9: OtgHsHcdma9,
    _reserved67: [u8; 0x08],
    otg_hs_hcchar10: OtgHsHcchar10,
    otg_hs_hcsplt10: OtgHsHcsplt10,
    otg_hs_hcint10: OtgHsHcint10,
    otg_hs_hcintmsk10: OtgHsHcintmsk10,
    otg_hs_hctsiz10: OtgHsHctsiz10,
    otg_hs_hcdma10: OtgHsHcdma10,
    _reserved73: [u8; 0x08],
    otg_hs_hcchar11: OtgHsHcchar11,
    otg_hs_hcsplt11: OtgHsHcsplt11,
    otg_hs_hcint11: OtgHsHcint11,
    otg_hs_hcintmsk11: OtgHsHcintmsk11,
    otg_hs_hctsiz11: OtgHsHctsiz11,
    otg_hs_hcdma11: OtgHsHcdma11,
    otg_hs_hcchar12: OtgHsHcchar12,
    otg_hs_hcsplt12: OtgHsHcsplt12,
    otg_hs_hcint12: OtgHsHcint12,
    otg_hs_hcintmsk12: OtgHsHcintmsk12,
    otg_hs_hctsiz12: OtgHsHctsiz12,
    otg_hs_hcdma12: OtgHsHcdma12,
    otg_hs_hcchar13: OtgHsHcchar13,
    otg_hs_hcsplt13: OtgHsHcsplt13,
    otg_hs_hcint13: OtgHsHcint13,
    otg_hs_hcintmsk13: OtgHsHcintmsk13,
    otg_hs_hctsiz13: OtgHsHctsiz13,
    otg_hs_hcdma13: OtgHsHcdma13,
    otg_hs_hcchar14: OtgHsHcchar14,
    otg_hs_hcsplt14: OtgHsHcsplt14,
    otg_hs_hcint14: OtgHsHcint14,
    otg_hs_hcintmsk14: OtgHsHcintmsk14,
    otg_hs_hctsiz14: OtgHsHctsiz14,
    otg_hs_hcdma14: OtgHsHcdma14,
    otg_hs_hcchar15: OtgHsHcchar15,
    otg_hs_hcsplt15: OtgHsHcsplt15,
    otg_hs_hcint15: OtgHsHcint15,
    otg_hs_hcintmsk15: OtgHsHcintmsk15,
    otg_hs_hctsiz15: OtgHsHctsiz15,
    otg_hs_hcdma15: OtgHsHcdma15,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_HS host configuration register"]
    #[inline(always)]
    pub const fn otg_hs_hcfg(&self) -> &OtgHsHcfg {
        &self.otg_hs_hcfg
    }
    #[doc = "0x04 - OTG_HS Host frame interval register"]
    #[inline(always)]
    pub const fn otg_hs_hfir(&self) -> &OtgHsHfir {
        &self.otg_hs_hfir
    }
    #[doc = "0x08 - OTG_HS host frame number/frame time remaining register"]
    #[inline(always)]
    pub const fn otg_hs_hfnum(&self) -> &OtgHsHfnum {
        &self.otg_hs_hfnum
    }
    #[doc = "0x10 - OTG_HS_Host periodic transmit FIFO/queue status register"]
    #[inline(always)]
    pub const fn otg_hs_hptxsts(&self) -> &OtgHsHptxsts {
        &self.otg_hs_hptxsts
    }
    #[doc = "0x14 - OTG_HS Host all channels interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_haint(&self) -> &OtgHsHaint {
        &self.otg_hs_haint
    }
    #[doc = "0x18 - OTG_HS host all channels interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_haintmsk(&self) -> &OtgHsHaintmsk {
        &self.otg_hs_haintmsk
    }
    #[doc = "0x40 - OTG_HS host port control and status register"]
    #[inline(always)]
    pub const fn otg_hs_hprt(&self) -> &OtgHsHprt {
        &self.otg_hs_hprt
    }
    #[doc = "0x100 - OTG_HS host channel-0 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar0(&self) -> &OtgHsHcchar0 {
        &self.otg_hs_hcchar0
    }
    #[doc = "0x104 - OTG_HS host channel-0 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt0(&self) -> &OtgHsHcsplt0 {
        &self.otg_hs_hcsplt0
    }
    #[doc = "0x108 - OTG_HS host channel-11 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint0(&self) -> &OtgHsHcint0 {
        &self.otg_hs_hcint0
    }
    #[doc = "0x10c - OTG_HS host channel-11 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk0(&self) -> &OtgHsHcintmsk0 {
        &self.otg_hs_hcintmsk0
    }
    #[doc = "0x110 - OTG_HS host channel-11 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz0(&self) -> &OtgHsHctsiz0 {
        &self.otg_hs_hctsiz0
    }
    #[doc = "0x114 - OTG_HS host channel-0 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma0(&self) -> &OtgHsHcdma0 {
        &self.otg_hs_hcdma0
    }
    #[doc = "0x120 - OTG_HS host channel-1 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar1(&self) -> &OtgHsHcchar1 {
        &self.otg_hs_hcchar1
    }
    #[doc = "0x124 - OTG_HS host channel-1 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt1(&self) -> &OtgHsHcsplt1 {
        &self.otg_hs_hcsplt1
    }
    #[doc = "0x128 - OTG_HS host channel-1 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint1(&self) -> &OtgHsHcint1 {
        &self.otg_hs_hcint1
    }
    #[doc = "0x12c - OTG_HS host channel-1 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk1(&self) -> &OtgHsHcintmsk1 {
        &self.otg_hs_hcintmsk1
    }
    #[doc = "0x130 - OTG_HS host channel-1 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz1(&self) -> &OtgHsHctsiz1 {
        &self.otg_hs_hctsiz1
    }
    #[doc = "0x134 - OTG_HS host channel-1 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma1(&self) -> &OtgHsHcdma1 {
        &self.otg_hs_hcdma1
    }
    #[doc = "0x140 - OTG_HS host channel-2 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar2(&self) -> &OtgHsHcchar2 {
        &self.otg_hs_hcchar2
    }
    #[doc = "0x144 - OTG_HS host channel-2 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt2(&self) -> &OtgHsHcsplt2 {
        &self.otg_hs_hcsplt2
    }
    #[doc = "0x148 - OTG_HS host channel-2 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint2(&self) -> &OtgHsHcint2 {
        &self.otg_hs_hcint2
    }
    #[doc = "0x14c - OTG_HS host channel-2 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk2(&self) -> &OtgHsHcintmsk2 {
        &self.otg_hs_hcintmsk2
    }
    #[doc = "0x150 - OTG_HS host channel-2 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz2(&self) -> &OtgHsHctsiz2 {
        &self.otg_hs_hctsiz2
    }
    #[doc = "0x154 - OTG_HS host channel-2 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma2(&self) -> &OtgHsHcdma2 {
        &self.otg_hs_hcdma2
    }
    #[doc = "0x160 - OTG_HS host channel-3 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar3(&self) -> &OtgHsHcchar3 {
        &self.otg_hs_hcchar3
    }
    #[doc = "0x164 - OTG_HS host channel-3 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt3(&self) -> &OtgHsHcsplt3 {
        &self.otg_hs_hcsplt3
    }
    #[doc = "0x168 - OTG_HS host channel-3 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint3(&self) -> &OtgHsHcint3 {
        &self.otg_hs_hcint3
    }
    #[doc = "0x16c - OTG_HS host channel-3 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk3(&self) -> &OtgHsHcintmsk3 {
        &self.otg_hs_hcintmsk3
    }
    #[doc = "0x170 - OTG_HS host channel-3 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz3(&self) -> &OtgHsHctsiz3 {
        &self.otg_hs_hctsiz3
    }
    #[doc = "0x174 - OTG_HS host channel-3 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma3(&self) -> &OtgHsHcdma3 {
        &self.otg_hs_hcdma3
    }
    #[doc = "0x180 - OTG_HS host channel-4 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar4(&self) -> &OtgHsHcchar4 {
        &self.otg_hs_hcchar4
    }
    #[doc = "0x184 - OTG_HS host channel-4 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt4(&self) -> &OtgHsHcsplt4 {
        &self.otg_hs_hcsplt4
    }
    #[doc = "0x188 - OTG_HS host channel-4 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint4(&self) -> &OtgHsHcint4 {
        &self.otg_hs_hcint4
    }
    #[doc = "0x18c - OTG_HS host channel-4 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk4(&self) -> &OtgHsHcintmsk4 {
        &self.otg_hs_hcintmsk4
    }
    #[doc = "0x190 - OTG_HS host channel-4 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz4(&self) -> &OtgHsHctsiz4 {
        &self.otg_hs_hctsiz4
    }
    #[doc = "0x194 - OTG_HS host channel-4 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma4(&self) -> &OtgHsHcdma4 {
        &self.otg_hs_hcdma4
    }
    #[doc = "0x1a0 - OTG_HS host channel-5 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar5(&self) -> &OtgHsHcchar5 {
        &self.otg_hs_hcchar5
    }
    #[doc = "0x1a4 - OTG_HS host channel-5 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt5(&self) -> &OtgHsHcsplt5 {
        &self.otg_hs_hcsplt5
    }
    #[doc = "0x1a8 - OTG_HS host channel-5 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint5(&self) -> &OtgHsHcint5 {
        &self.otg_hs_hcint5
    }
    #[doc = "0x1ac - OTG_HS host channel-5 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk5(&self) -> &OtgHsHcintmsk5 {
        &self.otg_hs_hcintmsk5
    }
    #[doc = "0x1b0 - OTG_HS host channel-5 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz5(&self) -> &OtgHsHctsiz5 {
        &self.otg_hs_hctsiz5
    }
    #[doc = "0x1b4 - OTG_HS host channel-5 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma5(&self) -> &OtgHsHcdma5 {
        &self.otg_hs_hcdma5
    }
    #[doc = "0x1c0 - OTG_HS host channel-6 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar6(&self) -> &OtgHsHcchar6 {
        &self.otg_hs_hcchar6
    }
    #[doc = "0x1c4 - OTG_HS host channel-6 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt6(&self) -> &OtgHsHcsplt6 {
        &self.otg_hs_hcsplt6
    }
    #[doc = "0x1c8 - OTG_HS host channel-6 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint6(&self) -> &OtgHsHcint6 {
        &self.otg_hs_hcint6
    }
    #[doc = "0x1cc - OTG_HS host channel-6 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk6(&self) -> &OtgHsHcintmsk6 {
        &self.otg_hs_hcintmsk6
    }
    #[doc = "0x1d0 - OTG_HS host channel-6 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz6(&self) -> &OtgHsHctsiz6 {
        &self.otg_hs_hctsiz6
    }
    #[doc = "0x1d4 - OTG_HS host channel-6 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma6(&self) -> &OtgHsHcdma6 {
        &self.otg_hs_hcdma6
    }
    #[doc = "0x1e0 - OTG_HS host channel-7 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar7(&self) -> &OtgHsHcchar7 {
        &self.otg_hs_hcchar7
    }
    #[doc = "0x1e4 - OTG_HS host channel-7 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt7(&self) -> &OtgHsHcsplt7 {
        &self.otg_hs_hcsplt7
    }
    #[doc = "0x1e8 - OTG_HS host channel-7 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint7(&self) -> &OtgHsHcint7 {
        &self.otg_hs_hcint7
    }
    #[doc = "0x1ec - OTG_HS host channel-7 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk7(&self) -> &OtgHsHcintmsk7 {
        &self.otg_hs_hcintmsk7
    }
    #[doc = "0x1f0 - OTG_HS host channel-7 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz7(&self) -> &OtgHsHctsiz7 {
        &self.otg_hs_hctsiz7
    }
    #[doc = "0x1f4 - OTG_HS host channel-7 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma7(&self) -> &OtgHsHcdma7 {
        &self.otg_hs_hcdma7
    }
    #[doc = "0x200 - OTG_HS host channel-8 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar8(&self) -> &OtgHsHcchar8 {
        &self.otg_hs_hcchar8
    }
    #[doc = "0x204 - OTG_HS host channel-8 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt8(&self) -> &OtgHsHcsplt8 {
        &self.otg_hs_hcsplt8
    }
    #[doc = "0x208 - OTG_HS host channel-8 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint8(&self) -> &OtgHsHcint8 {
        &self.otg_hs_hcint8
    }
    #[doc = "0x20c - OTG_HS host channel-8 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk8(&self) -> &OtgHsHcintmsk8 {
        &self.otg_hs_hcintmsk8
    }
    #[doc = "0x210 - OTG_HS host channel-8 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz8(&self) -> &OtgHsHctsiz8 {
        &self.otg_hs_hctsiz8
    }
    #[doc = "0x214 - OTG_HS host channel-8 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma8(&self) -> &OtgHsHcdma8 {
        &self.otg_hs_hcdma8
    }
    #[doc = "0x220 - OTG_HS host channel-9 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar9(&self) -> &OtgHsHcchar9 {
        &self.otg_hs_hcchar9
    }
    #[doc = "0x224 - OTG_HS host channel-9 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt9(&self) -> &OtgHsHcsplt9 {
        &self.otg_hs_hcsplt9
    }
    #[doc = "0x228 - OTG_HS host channel-9 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint9(&self) -> &OtgHsHcint9 {
        &self.otg_hs_hcint9
    }
    #[doc = "0x22c - OTG_HS host channel-9 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk9(&self) -> &OtgHsHcintmsk9 {
        &self.otg_hs_hcintmsk9
    }
    #[doc = "0x230 - OTG_HS host channel-9 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz9(&self) -> &OtgHsHctsiz9 {
        &self.otg_hs_hctsiz9
    }
    #[doc = "0x234 - OTG_HS host channel-9 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma9(&self) -> &OtgHsHcdma9 {
        &self.otg_hs_hcdma9
    }
    #[doc = "0x240 - OTG_HS host channel-10 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar10(&self) -> &OtgHsHcchar10 {
        &self.otg_hs_hcchar10
    }
    #[doc = "0x244 - OTG_HS host channel-10 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt10(&self) -> &OtgHsHcsplt10 {
        &self.otg_hs_hcsplt10
    }
    #[doc = "0x248 - OTG_HS host channel-10 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint10(&self) -> &OtgHsHcint10 {
        &self.otg_hs_hcint10
    }
    #[doc = "0x24c - OTG_HS host channel-10 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk10(&self) -> &OtgHsHcintmsk10 {
        &self.otg_hs_hcintmsk10
    }
    #[doc = "0x250 - OTG_HS host channel-10 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz10(&self) -> &OtgHsHctsiz10 {
        &self.otg_hs_hctsiz10
    }
    #[doc = "0x254 - OTG_HS host channel-10 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma10(&self) -> &OtgHsHcdma10 {
        &self.otg_hs_hcdma10
    }
    #[doc = "0x260 - OTG_HS host channel-11 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar11(&self) -> &OtgHsHcchar11 {
        &self.otg_hs_hcchar11
    }
    #[doc = "0x264 - OTG_HS host channel-11 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt11(&self) -> &OtgHsHcsplt11 {
        &self.otg_hs_hcsplt11
    }
    #[doc = "0x268 - OTG_HS host channel-11 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint11(&self) -> &OtgHsHcint11 {
        &self.otg_hs_hcint11
    }
    #[doc = "0x26c - OTG_HS host channel-11 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk11(&self) -> &OtgHsHcintmsk11 {
        &self.otg_hs_hcintmsk11
    }
    #[doc = "0x270 - OTG_HS host channel-11 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz11(&self) -> &OtgHsHctsiz11 {
        &self.otg_hs_hctsiz11
    }
    #[doc = "0x274 - OTG_HS host channel-11 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma11(&self) -> &OtgHsHcdma11 {
        &self.otg_hs_hcdma11
    }
    #[doc = "0x278 - OTG_HS host channel-12 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar12(&self) -> &OtgHsHcchar12 {
        &self.otg_hs_hcchar12
    }
    #[doc = "0x27c - OTG_HS host channel-12 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt12(&self) -> &OtgHsHcsplt12 {
        &self.otg_hs_hcsplt12
    }
    #[doc = "0x280 - OTG_HS host channel-12 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint12(&self) -> &OtgHsHcint12 {
        &self.otg_hs_hcint12
    }
    #[doc = "0x284 - OTG_HS host channel-12 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk12(&self) -> &OtgHsHcintmsk12 {
        &self.otg_hs_hcintmsk12
    }
    #[doc = "0x288 - OTG_HS host channel-12 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz12(&self) -> &OtgHsHctsiz12 {
        &self.otg_hs_hctsiz12
    }
    #[doc = "0x28c - OTG_HS host channel-12 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma12(&self) -> &OtgHsHcdma12 {
        &self.otg_hs_hcdma12
    }
    #[doc = "0x290 - OTG_HS host channel-13 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar13(&self) -> &OtgHsHcchar13 {
        &self.otg_hs_hcchar13
    }
    #[doc = "0x294 - OTG_HS host channel-13 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt13(&self) -> &OtgHsHcsplt13 {
        &self.otg_hs_hcsplt13
    }
    #[doc = "0x298 - OTG_HS host channel-13 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint13(&self) -> &OtgHsHcint13 {
        &self.otg_hs_hcint13
    }
    #[doc = "0x29c - OTG_HS host channel-13 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk13(&self) -> &OtgHsHcintmsk13 {
        &self.otg_hs_hcintmsk13
    }
    #[doc = "0x2a0 - OTG_HS host channel-13 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz13(&self) -> &OtgHsHctsiz13 {
        &self.otg_hs_hctsiz13
    }
    #[doc = "0x2a4 - OTG_HS host channel-13 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma13(&self) -> &OtgHsHcdma13 {
        &self.otg_hs_hcdma13
    }
    #[doc = "0x2a8 - OTG_HS host channel-14 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar14(&self) -> &OtgHsHcchar14 {
        &self.otg_hs_hcchar14
    }
    #[doc = "0x2ac - OTG_HS host channel-14 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt14(&self) -> &OtgHsHcsplt14 {
        &self.otg_hs_hcsplt14
    }
    #[doc = "0x2b0 - OTG_HS host channel-14 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint14(&self) -> &OtgHsHcint14 {
        &self.otg_hs_hcint14
    }
    #[doc = "0x2b4 - OTG_HS host channel-14 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk14(&self) -> &OtgHsHcintmsk14 {
        &self.otg_hs_hcintmsk14
    }
    #[doc = "0x2b8 - OTG_HS host channel-14 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz14(&self) -> &OtgHsHctsiz14 {
        &self.otg_hs_hctsiz14
    }
    #[doc = "0x2bc - OTG_HS host channel-14 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma14(&self) -> &OtgHsHcdma14 {
        &self.otg_hs_hcdma14
    }
    #[doc = "0x2c0 - OTG_HS host channel-15 characteristics register"]
    #[inline(always)]
    pub const fn otg_hs_hcchar15(&self) -> &OtgHsHcchar15 {
        &self.otg_hs_hcchar15
    }
    #[doc = "0x2c4 - OTG_HS host channel-15 split control register"]
    #[inline(always)]
    pub const fn otg_hs_hcsplt15(&self) -> &OtgHsHcsplt15 {
        &self.otg_hs_hcsplt15
    }
    #[doc = "0x2c8 - OTG_HS host channel-15 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_hcint15(&self) -> &OtgHsHcint15 {
        &self.otg_hs_hcint15
    }
    #[doc = "0x2cc - OTG_HS host channel-15 interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_hcintmsk15(&self) -> &OtgHsHcintmsk15 {
        &self.otg_hs_hcintmsk15
    }
    #[doc = "0x2d0 - OTG_HS host channel-15 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_hctsiz15(&self) -> &OtgHsHctsiz15 {
        &self.otg_hs_hctsiz15
    }
    #[doc = "0x2d4 - OTG_HS host channel-15 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_hcdma15(&self) -> &OtgHsHcdma15 {
        &self.otg_hs_hcdma15
    }
}
#[doc = "OTG_HS_HCFG (rw) register accessor: OTG_HS host configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcfg`]
module"]
#[doc(alias = "OTG_HS_HCFG")]
pub type OtgHsHcfg = crate::Reg<otg_hs_hcfg::OtgHsHcfgSpec>;
#[doc = "OTG_HS host configuration register"]
pub mod otg_hs_hcfg;
#[doc = "OTG_HS_HFIR (rw) register accessor: OTG_HS Host frame interval register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hfir::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hfir::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hfir`]
module"]
#[doc(alias = "OTG_HS_HFIR")]
pub type OtgHsHfir = crate::Reg<otg_hs_hfir::OtgHsHfirSpec>;
#[doc = "OTG_HS Host frame interval register"]
pub mod otg_hs_hfir;
#[doc = "OTG_HS_HFNUM (r) register accessor: OTG_HS host frame number/frame time remaining register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hfnum::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hfnum`]
module"]
#[doc(alias = "OTG_HS_HFNUM")]
pub type OtgHsHfnum = crate::Reg<otg_hs_hfnum::OtgHsHfnumSpec>;
#[doc = "OTG_HS host frame number/frame time remaining register"]
pub mod otg_hs_hfnum;
#[doc = "OTG_HS_HPTXSTS (rw) register accessor: OTG_HS_Host periodic transmit FIFO/queue status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hptxsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hptxsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hptxsts`]
module"]
#[doc(alias = "OTG_HS_HPTXSTS")]
pub type OtgHsHptxsts = crate::Reg<otg_hs_hptxsts::OtgHsHptxstsSpec>;
#[doc = "OTG_HS_Host periodic transmit FIFO/queue status register"]
pub mod otg_hs_hptxsts;
#[doc = "OTG_HS_HAINT (r) register accessor: OTG_HS Host all channels interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_haint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_haint`]
module"]
#[doc(alias = "OTG_HS_HAINT")]
pub type OtgHsHaint = crate::Reg<otg_hs_haint::OtgHsHaintSpec>;
#[doc = "OTG_HS Host all channels interrupt register"]
pub mod otg_hs_haint;
#[doc = "OTG_HS_HAINTMSK (rw) register accessor: OTG_HS host all channels interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_haintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_haintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_haintmsk`]
module"]
#[doc(alias = "OTG_HS_HAINTMSK")]
pub type OtgHsHaintmsk = crate::Reg<otg_hs_haintmsk::OtgHsHaintmskSpec>;
#[doc = "OTG_HS host all channels interrupt mask register"]
pub mod otg_hs_haintmsk;
#[doc = "OTG_HS_HPRT (rw) register accessor: OTG_HS host port control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hprt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hprt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hprt`]
module"]
#[doc(alias = "OTG_HS_HPRT")]
pub type OtgHsHprt = crate::Reg<otg_hs_hprt::OtgHsHprtSpec>;
#[doc = "OTG_HS host port control and status register"]
pub mod otg_hs_hprt;
#[doc = "OTG_HS_HCCHAR0 (rw) register accessor: OTG_HS host channel-0 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar0`]
module"]
#[doc(alias = "OTG_HS_HCCHAR0")]
pub type OtgHsHcchar0 = crate::Reg<otg_hs_hcchar0::OtgHsHcchar0Spec>;
#[doc = "OTG_HS host channel-0 characteristics register"]
pub mod otg_hs_hcchar0;
#[doc = "OTG_HS_HCCHAR1 (rw) register accessor: OTG_HS host channel-1 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar1`]
module"]
#[doc(alias = "OTG_HS_HCCHAR1")]
pub type OtgHsHcchar1 = crate::Reg<otg_hs_hcchar1::OtgHsHcchar1Spec>;
#[doc = "OTG_HS host channel-1 characteristics register"]
pub mod otg_hs_hcchar1;
#[doc = "OTG_HS_HCCHAR2 (rw) register accessor: OTG_HS host channel-2 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar2`]
module"]
#[doc(alias = "OTG_HS_HCCHAR2")]
pub type OtgHsHcchar2 = crate::Reg<otg_hs_hcchar2::OtgHsHcchar2Spec>;
#[doc = "OTG_HS host channel-2 characteristics register"]
pub mod otg_hs_hcchar2;
#[doc = "OTG_HS_HCCHAR3 (rw) register accessor: OTG_HS host channel-3 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar3`]
module"]
#[doc(alias = "OTG_HS_HCCHAR3")]
pub type OtgHsHcchar3 = crate::Reg<otg_hs_hcchar3::OtgHsHcchar3Spec>;
#[doc = "OTG_HS host channel-3 characteristics register"]
pub mod otg_hs_hcchar3;
#[doc = "OTG_HS_HCCHAR4 (rw) register accessor: OTG_HS host channel-4 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar4`]
module"]
#[doc(alias = "OTG_HS_HCCHAR4")]
pub type OtgHsHcchar4 = crate::Reg<otg_hs_hcchar4::OtgHsHcchar4Spec>;
#[doc = "OTG_HS host channel-4 characteristics register"]
pub mod otg_hs_hcchar4;
#[doc = "OTG_HS_HCCHAR5 (rw) register accessor: OTG_HS host channel-5 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar5`]
module"]
#[doc(alias = "OTG_HS_HCCHAR5")]
pub type OtgHsHcchar5 = crate::Reg<otg_hs_hcchar5::OtgHsHcchar5Spec>;
#[doc = "OTG_HS host channel-5 characteristics register"]
pub mod otg_hs_hcchar5;
#[doc = "OTG_HS_HCCHAR6 (rw) register accessor: OTG_HS host channel-6 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar6`]
module"]
#[doc(alias = "OTG_HS_HCCHAR6")]
pub type OtgHsHcchar6 = crate::Reg<otg_hs_hcchar6::OtgHsHcchar6Spec>;
#[doc = "OTG_HS host channel-6 characteristics register"]
pub mod otg_hs_hcchar6;
#[doc = "OTG_HS_HCCHAR7 (rw) register accessor: OTG_HS host channel-7 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar7`]
module"]
#[doc(alias = "OTG_HS_HCCHAR7")]
pub type OtgHsHcchar7 = crate::Reg<otg_hs_hcchar7::OtgHsHcchar7Spec>;
#[doc = "OTG_HS host channel-7 characteristics register"]
pub mod otg_hs_hcchar7;
#[doc = "OTG_HS_HCCHAR8 (rw) register accessor: OTG_HS host channel-8 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar8`]
module"]
#[doc(alias = "OTG_HS_HCCHAR8")]
pub type OtgHsHcchar8 = crate::Reg<otg_hs_hcchar8::OtgHsHcchar8Spec>;
#[doc = "OTG_HS host channel-8 characteristics register"]
pub mod otg_hs_hcchar8;
#[doc = "OTG_HS_HCCHAR9 (rw) register accessor: OTG_HS host channel-9 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar9`]
module"]
#[doc(alias = "OTG_HS_HCCHAR9")]
pub type OtgHsHcchar9 = crate::Reg<otg_hs_hcchar9::OtgHsHcchar9Spec>;
#[doc = "OTG_HS host channel-9 characteristics register"]
pub mod otg_hs_hcchar9;
#[doc = "OTG_HS_HCCHAR10 (rw) register accessor: OTG_HS host channel-10 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar10`]
module"]
#[doc(alias = "OTG_HS_HCCHAR10")]
pub type OtgHsHcchar10 = crate::Reg<otg_hs_hcchar10::OtgHsHcchar10Spec>;
#[doc = "OTG_HS host channel-10 characteristics register"]
pub mod otg_hs_hcchar10;
#[doc = "OTG_HS_HCCHAR11 (rw) register accessor: OTG_HS host channel-11 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar11`]
module"]
#[doc(alias = "OTG_HS_HCCHAR11")]
pub type OtgHsHcchar11 = crate::Reg<otg_hs_hcchar11::OtgHsHcchar11Spec>;
#[doc = "OTG_HS host channel-11 characteristics register"]
pub mod otg_hs_hcchar11;
#[doc = "OTG_HS_HCSPLT0 (rw) register accessor: OTG_HS host channel-0 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt0`]
module"]
#[doc(alias = "OTG_HS_HCSPLT0")]
pub type OtgHsHcsplt0 = crate::Reg<otg_hs_hcsplt0::OtgHsHcsplt0Spec>;
#[doc = "OTG_HS host channel-0 split control register"]
pub mod otg_hs_hcsplt0;
#[doc = "OTG_HS_HCSPLT1 (rw) register accessor: OTG_HS host channel-1 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt1`]
module"]
#[doc(alias = "OTG_HS_HCSPLT1")]
pub type OtgHsHcsplt1 = crate::Reg<otg_hs_hcsplt1::OtgHsHcsplt1Spec>;
#[doc = "OTG_HS host channel-1 split control register"]
pub mod otg_hs_hcsplt1;
#[doc = "OTG_HS_HCSPLT2 (rw) register accessor: OTG_HS host channel-2 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt2`]
module"]
#[doc(alias = "OTG_HS_HCSPLT2")]
pub type OtgHsHcsplt2 = crate::Reg<otg_hs_hcsplt2::OtgHsHcsplt2Spec>;
#[doc = "OTG_HS host channel-2 split control register"]
pub mod otg_hs_hcsplt2;
#[doc = "OTG_HS_HCSPLT3 (rw) register accessor: OTG_HS host channel-3 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt3`]
module"]
#[doc(alias = "OTG_HS_HCSPLT3")]
pub type OtgHsHcsplt3 = crate::Reg<otg_hs_hcsplt3::OtgHsHcsplt3Spec>;
#[doc = "OTG_HS host channel-3 split control register"]
pub mod otg_hs_hcsplt3;
#[doc = "OTG_HS_HCSPLT4 (rw) register accessor: OTG_HS host channel-4 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt4`]
module"]
#[doc(alias = "OTG_HS_HCSPLT4")]
pub type OtgHsHcsplt4 = crate::Reg<otg_hs_hcsplt4::OtgHsHcsplt4Spec>;
#[doc = "OTG_HS host channel-4 split control register"]
pub mod otg_hs_hcsplt4;
#[doc = "OTG_HS_HCSPLT5 (rw) register accessor: OTG_HS host channel-5 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt5`]
module"]
#[doc(alias = "OTG_HS_HCSPLT5")]
pub type OtgHsHcsplt5 = crate::Reg<otg_hs_hcsplt5::OtgHsHcsplt5Spec>;
#[doc = "OTG_HS host channel-5 split control register"]
pub mod otg_hs_hcsplt5;
#[doc = "OTG_HS_HCSPLT6 (rw) register accessor: OTG_HS host channel-6 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt6`]
module"]
#[doc(alias = "OTG_HS_HCSPLT6")]
pub type OtgHsHcsplt6 = crate::Reg<otg_hs_hcsplt6::OtgHsHcsplt6Spec>;
#[doc = "OTG_HS host channel-6 split control register"]
pub mod otg_hs_hcsplt6;
#[doc = "OTG_HS_HCSPLT7 (rw) register accessor: OTG_HS host channel-7 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt7`]
module"]
#[doc(alias = "OTG_HS_HCSPLT7")]
pub type OtgHsHcsplt7 = crate::Reg<otg_hs_hcsplt7::OtgHsHcsplt7Spec>;
#[doc = "OTG_HS host channel-7 split control register"]
pub mod otg_hs_hcsplt7;
#[doc = "OTG_HS_HCSPLT8 (rw) register accessor: OTG_HS host channel-8 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt8`]
module"]
#[doc(alias = "OTG_HS_HCSPLT8")]
pub type OtgHsHcsplt8 = crate::Reg<otg_hs_hcsplt8::OtgHsHcsplt8Spec>;
#[doc = "OTG_HS host channel-8 split control register"]
pub mod otg_hs_hcsplt8;
#[doc = "OTG_HS_HCSPLT9 (rw) register accessor: OTG_HS host channel-9 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt9`]
module"]
#[doc(alias = "OTG_HS_HCSPLT9")]
pub type OtgHsHcsplt9 = crate::Reg<otg_hs_hcsplt9::OtgHsHcsplt9Spec>;
#[doc = "OTG_HS host channel-9 split control register"]
pub mod otg_hs_hcsplt9;
#[doc = "OTG_HS_HCSPLT10 (rw) register accessor: OTG_HS host channel-10 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt10`]
module"]
#[doc(alias = "OTG_HS_HCSPLT10")]
pub type OtgHsHcsplt10 = crate::Reg<otg_hs_hcsplt10::OtgHsHcsplt10Spec>;
#[doc = "OTG_HS host channel-10 split control register"]
pub mod otg_hs_hcsplt10;
#[doc = "OTG_HS_HCSPLT11 (rw) register accessor: OTG_HS host channel-11 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt11`]
module"]
#[doc(alias = "OTG_HS_HCSPLT11")]
pub type OtgHsHcsplt11 = crate::Reg<otg_hs_hcsplt11::OtgHsHcsplt11Spec>;
#[doc = "OTG_HS host channel-11 split control register"]
pub mod otg_hs_hcsplt11;
#[doc = "OTG_HS_HCINT0 (rw) register accessor: OTG_HS host channel-11 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint0`]
module"]
#[doc(alias = "OTG_HS_HCINT0")]
pub type OtgHsHcint0 = crate::Reg<otg_hs_hcint0::OtgHsHcint0Spec>;
#[doc = "OTG_HS host channel-11 interrupt register"]
pub mod otg_hs_hcint0;
#[doc = "OTG_HS_HCINT1 (rw) register accessor: OTG_HS host channel-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint1`]
module"]
#[doc(alias = "OTG_HS_HCINT1")]
pub type OtgHsHcint1 = crate::Reg<otg_hs_hcint1::OtgHsHcint1Spec>;
#[doc = "OTG_HS host channel-1 interrupt register"]
pub mod otg_hs_hcint1;
#[doc = "OTG_HS_HCINT2 (rw) register accessor: OTG_HS host channel-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint2`]
module"]
#[doc(alias = "OTG_HS_HCINT2")]
pub type OtgHsHcint2 = crate::Reg<otg_hs_hcint2::OtgHsHcint2Spec>;
#[doc = "OTG_HS host channel-2 interrupt register"]
pub mod otg_hs_hcint2;
#[doc = "OTG_HS_HCINT3 (rw) register accessor: OTG_HS host channel-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint3`]
module"]
#[doc(alias = "OTG_HS_HCINT3")]
pub type OtgHsHcint3 = crate::Reg<otg_hs_hcint3::OtgHsHcint3Spec>;
#[doc = "OTG_HS host channel-3 interrupt register"]
pub mod otg_hs_hcint3;
#[doc = "OTG_HS_HCINT4 (rw) register accessor: OTG_HS host channel-4 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint4`]
module"]
#[doc(alias = "OTG_HS_HCINT4")]
pub type OtgHsHcint4 = crate::Reg<otg_hs_hcint4::OtgHsHcint4Spec>;
#[doc = "OTG_HS host channel-4 interrupt register"]
pub mod otg_hs_hcint4;
#[doc = "OTG_HS_HCINT5 (rw) register accessor: OTG_HS host channel-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint5`]
module"]
#[doc(alias = "OTG_HS_HCINT5")]
pub type OtgHsHcint5 = crate::Reg<otg_hs_hcint5::OtgHsHcint5Spec>;
#[doc = "OTG_HS host channel-5 interrupt register"]
pub mod otg_hs_hcint5;
#[doc = "OTG_HS_HCINT6 (rw) register accessor: OTG_HS host channel-6 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint6`]
module"]
#[doc(alias = "OTG_HS_HCINT6")]
pub type OtgHsHcint6 = crate::Reg<otg_hs_hcint6::OtgHsHcint6Spec>;
#[doc = "OTG_HS host channel-6 interrupt register"]
pub mod otg_hs_hcint6;
#[doc = "OTG_HS_HCINT7 (rw) register accessor: OTG_HS host channel-7 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint7`]
module"]
#[doc(alias = "OTG_HS_HCINT7")]
pub type OtgHsHcint7 = crate::Reg<otg_hs_hcint7::OtgHsHcint7Spec>;
#[doc = "OTG_HS host channel-7 interrupt register"]
pub mod otg_hs_hcint7;
#[doc = "OTG_HS_HCINT8 (rw) register accessor: OTG_HS host channel-8 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint8`]
module"]
#[doc(alias = "OTG_HS_HCINT8")]
pub type OtgHsHcint8 = crate::Reg<otg_hs_hcint8::OtgHsHcint8Spec>;
#[doc = "OTG_HS host channel-8 interrupt register"]
pub mod otg_hs_hcint8;
#[doc = "OTG_HS_HCINT9 (rw) register accessor: OTG_HS host channel-9 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint9`]
module"]
#[doc(alias = "OTG_HS_HCINT9")]
pub type OtgHsHcint9 = crate::Reg<otg_hs_hcint9::OtgHsHcint9Spec>;
#[doc = "OTG_HS host channel-9 interrupt register"]
pub mod otg_hs_hcint9;
#[doc = "OTG_HS_HCINT10 (rw) register accessor: OTG_HS host channel-10 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint10`]
module"]
#[doc(alias = "OTG_HS_HCINT10")]
pub type OtgHsHcint10 = crate::Reg<otg_hs_hcint10::OtgHsHcint10Spec>;
#[doc = "OTG_HS host channel-10 interrupt register"]
pub mod otg_hs_hcint10;
#[doc = "OTG_HS_HCINT11 (rw) register accessor: OTG_HS host channel-11 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint11`]
module"]
#[doc(alias = "OTG_HS_HCINT11")]
pub type OtgHsHcint11 = crate::Reg<otg_hs_hcint11::OtgHsHcint11Spec>;
#[doc = "OTG_HS host channel-11 interrupt register"]
pub mod otg_hs_hcint11;
#[doc = "OTG_HS_HCINTMSK0 (rw) register accessor: OTG_HS host channel-11 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk0`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK0")]
pub type OtgHsHcintmsk0 = crate::Reg<otg_hs_hcintmsk0::OtgHsHcintmsk0Spec>;
#[doc = "OTG_HS host channel-11 interrupt mask register"]
pub mod otg_hs_hcintmsk0;
#[doc = "OTG_HS_HCINTMSK1 (rw) register accessor: OTG_HS host channel-1 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk1`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK1")]
pub type OtgHsHcintmsk1 = crate::Reg<otg_hs_hcintmsk1::OtgHsHcintmsk1Spec>;
#[doc = "OTG_HS host channel-1 interrupt mask register"]
pub mod otg_hs_hcintmsk1;
#[doc = "OTG_HS_HCINTMSK2 (rw) register accessor: OTG_HS host channel-2 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk2`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK2")]
pub type OtgHsHcintmsk2 = crate::Reg<otg_hs_hcintmsk2::OtgHsHcintmsk2Spec>;
#[doc = "OTG_HS host channel-2 interrupt mask register"]
pub mod otg_hs_hcintmsk2;
#[doc = "OTG_HS_HCINTMSK3 (rw) register accessor: OTG_HS host channel-3 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk3`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK3")]
pub type OtgHsHcintmsk3 = crate::Reg<otg_hs_hcintmsk3::OtgHsHcintmsk3Spec>;
#[doc = "OTG_HS host channel-3 interrupt mask register"]
pub mod otg_hs_hcintmsk3;
#[doc = "OTG_HS_HCINTMSK4 (rw) register accessor: OTG_HS host channel-4 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk4`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK4")]
pub type OtgHsHcintmsk4 = crate::Reg<otg_hs_hcintmsk4::OtgHsHcintmsk4Spec>;
#[doc = "OTG_HS host channel-4 interrupt mask register"]
pub mod otg_hs_hcintmsk4;
#[doc = "OTG_HS_HCINTMSK5 (rw) register accessor: OTG_HS host channel-5 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk5`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK5")]
pub type OtgHsHcintmsk5 = crate::Reg<otg_hs_hcintmsk5::OtgHsHcintmsk5Spec>;
#[doc = "OTG_HS host channel-5 interrupt mask register"]
pub mod otg_hs_hcintmsk5;
#[doc = "OTG_HS_HCINTMSK6 (rw) register accessor: OTG_HS host channel-6 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk6`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK6")]
pub type OtgHsHcintmsk6 = crate::Reg<otg_hs_hcintmsk6::OtgHsHcintmsk6Spec>;
#[doc = "OTG_HS host channel-6 interrupt mask register"]
pub mod otg_hs_hcintmsk6;
#[doc = "OTG_HS_HCINTMSK7 (rw) register accessor: OTG_HS host channel-7 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk7`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK7")]
pub type OtgHsHcintmsk7 = crate::Reg<otg_hs_hcintmsk7::OtgHsHcintmsk7Spec>;
#[doc = "OTG_HS host channel-7 interrupt mask register"]
pub mod otg_hs_hcintmsk7;
#[doc = "OTG_HS_HCINTMSK8 (rw) register accessor: OTG_HS host channel-8 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk8`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK8")]
pub type OtgHsHcintmsk8 = crate::Reg<otg_hs_hcintmsk8::OtgHsHcintmsk8Spec>;
#[doc = "OTG_HS host channel-8 interrupt mask register"]
pub mod otg_hs_hcintmsk8;
#[doc = "OTG_HS_HCINTMSK9 (rw) register accessor: OTG_HS host channel-9 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk9`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK9")]
pub type OtgHsHcintmsk9 = crate::Reg<otg_hs_hcintmsk9::OtgHsHcintmsk9Spec>;
#[doc = "OTG_HS host channel-9 interrupt mask register"]
pub mod otg_hs_hcintmsk9;
#[doc = "OTG_HS_HCINTMSK10 (rw) register accessor: OTG_HS host channel-10 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk10`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK10")]
pub type OtgHsHcintmsk10 = crate::Reg<otg_hs_hcintmsk10::OtgHsHcintmsk10Spec>;
#[doc = "OTG_HS host channel-10 interrupt mask register"]
pub mod otg_hs_hcintmsk10;
#[doc = "OTG_HS_HCINTMSK11 (rw) register accessor: OTG_HS host channel-11 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk11`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK11")]
pub type OtgHsHcintmsk11 = crate::Reg<otg_hs_hcintmsk11::OtgHsHcintmsk11Spec>;
#[doc = "OTG_HS host channel-11 interrupt mask register"]
pub mod otg_hs_hcintmsk11;
#[doc = "OTG_HS_HCTSIZ0 (rw) register accessor: OTG_HS host channel-11 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz0`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ0")]
pub type OtgHsHctsiz0 = crate::Reg<otg_hs_hctsiz0::OtgHsHctsiz0Spec>;
#[doc = "OTG_HS host channel-11 transfer size register"]
pub mod otg_hs_hctsiz0;
#[doc = "OTG_HS_HCTSIZ1 (rw) register accessor: OTG_HS host channel-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz1`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ1")]
pub type OtgHsHctsiz1 = crate::Reg<otg_hs_hctsiz1::OtgHsHctsiz1Spec>;
#[doc = "OTG_HS host channel-1 transfer size register"]
pub mod otg_hs_hctsiz1;
#[doc = "OTG_HS_HCTSIZ2 (rw) register accessor: OTG_HS host channel-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz2`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ2")]
pub type OtgHsHctsiz2 = crate::Reg<otg_hs_hctsiz2::OtgHsHctsiz2Spec>;
#[doc = "OTG_HS host channel-2 transfer size register"]
pub mod otg_hs_hctsiz2;
#[doc = "OTG_HS_HCTSIZ3 (rw) register accessor: OTG_HS host channel-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz3`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ3")]
pub type OtgHsHctsiz3 = crate::Reg<otg_hs_hctsiz3::OtgHsHctsiz3Spec>;
#[doc = "OTG_HS host channel-3 transfer size register"]
pub mod otg_hs_hctsiz3;
#[doc = "OTG_HS_HCTSIZ4 (rw) register accessor: OTG_HS host channel-4 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz4`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ4")]
pub type OtgHsHctsiz4 = crate::Reg<otg_hs_hctsiz4::OtgHsHctsiz4Spec>;
#[doc = "OTG_HS host channel-4 transfer size register"]
pub mod otg_hs_hctsiz4;
#[doc = "OTG_HS_HCTSIZ5 (rw) register accessor: OTG_HS host channel-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz5`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ5")]
pub type OtgHsHctsiz5 = crate::Reg<otg_hs_hctsiz5::OtgHsHctsiz5Spec>;
#[doc = "OTG_HS host channel-5 transfer size register"]
pub mod otg_hs_hctsiz5;
#[doc = "OTG_HS_HCTSIZ6 (rw) register accessor: OTG_HS host channel-6 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz6`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ6")]
pub type OtgHsHctsiz6 = crate::Reg<otg_hs_hctsiz6::OtgHsHctsiz6Spec>;
#[doc = "OTG_HS host channel-6 transfer size register"]
pub mod otg_hs_hctsiz6;
#[doc = "OTG_HS_HCTSIZ7 (rw) register accessor: OTG_HS host channel-7 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz7`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ7")]
pub type OtgHsHctsiz7 = crate::Reg<otg_hs_hctsiz7::OtgHsHctsiz7Spec>;
#[doc = "OTG_HS host channel-7 transfer size register"]
pub mod otg_hs_hctsiz7;
#[doc = "OTG_HS_HCTSIZ8 (rw) register accessor: OTG_HS host channel-8 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz8`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ8")]
pub type OtgHsHctsiz8 = crate::Reg<otg_hs_hctsiz8::OtgHsHctsiz8Spec>;
#[doc = "OTG_HS host channel-8 transfer size register"]
pub mod otg_hs_hctsiz8;
#[doc = "OTG_HS_HCTSIZ9 (rw) register accessor: OTG_HS host channel-9 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz9`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ9")]
pub type OtgHsHctsiz9 = crate::Reg<otg_hs_hctsiz9::OtgHsHctsiz9Spec>;
#[doc = "OTG_HS host channel-9 transfer size register"]
pub mod otg_hs_hctsiz9;
#[doc = "OTG_HS_HCTSIZ10 (rw) register accessor: OTG_HS host channel-10 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz10`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ10")]
pub type OtgHsHctsiz10 = crate::Reg<otg_hs_hctsiz10::OtgHsHctsiz10Spec>;
#[doc = "OTG_HS host channel-10 transfer size register"]
pub mod otg_hs_hctsiz10;
#[doc = "OTG_HS_HCTSIZ11 (rw) register accessor: OTG_HS host channel-11 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz11`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ11")]
pub type OtgHsHctsiz11 = crate::Reg<otg_hs_hctsiz11::OtgHsHctsiz11Spec>;
#[doc = "OTG_HS host channel-11 transfer size register"]
pub mod otg_hs_hctsiz11;
#[doc = "OTG_HS_HCDMA0 (rw) register accessor: OTG_HS host channel-0 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma0`]
module"]
#[doc(alias = "OTG_HS_HCDMA0")]
pub type OtgHsHcdma0 = crate::Reg<otg_hs_hcdma0::OtgHsHcdma0Spec>;
#[doc = "OTG_HS host channel-0 DMA address register"]
pub mod otg_hs_hcdma0;
#[doc = "OTG_HS_HCDMA1 (rw) register accessor: OTG_HS host channel-1 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma1`]
module"]
#[doc(alias = "OTG_HS_HCDMA1")]
pub type OtgHsHcdma1 = crate::Reg<otg_hs_hcdma1::OtgHsHcdma1Spec>;
#[doc = "OTG_HS host channel-1 DMA address register"]
pub mod otg_hs_hcdma1;
#[doc = "OTG_HS_HCDMA2 (rw) register accessor: OTG_HS host channel-2 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma2`]
module"]
#[doc(alias = "OTG_HS_HCDMA2")]
pub type OtgHsHcdma2 = crate::Reg<otg_hs_hcdma2::OtgHsHcdma2Spec>;
#[doc = "OTG_HS host channel-2 DMA address register"]
pub mod otg_hs_hcdma2;
#[doc = "OTG_HS_HCDMA3 (rw) register accessor: OTG_HS host channel-3 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma3`]
module"]
#[doc(alias = "OTG_HS_HCDMA3")]
pub type OtgHsHcdma3 = crate::Reg<otg_hs_hcdma3::OtgHsHcdma3Spec>;
#[doc = "OTG_HS host channel-3 DMA address register"]
pub mod otg_hs_hcdma3;
#[doc = "OTG_HS_HCDMA4 (rw) register accessor: OTG_HS host channel-4 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma4`]
module"]
#[doc(alias = "OTG_HS_HCDMA4")]
pub type OtgHsHcdma4 = crate::Reg<otg_hs_hcdma4::OtgHsHcdma4Spec>;
#[doc = "OTG_HS host channel-4 DMA address register"]
pub mod otg_hs_hcdma4;
#[doc = "OTG_HS_HCDMA5 (rw) register accessor: OTG_HS host channel-5 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma5`]
module"]
#[doc(alias = "OTG_HS_HCDMA5")]
pub type OtgHsHcdma5 = crate::Reg<otg_hs_hcdma5::OtgHsHcdma5Spec>;
#[doc = "OTG_HS host channel-5 DMA address register"]
pub mod otg_hs_hcdma5;
#[doc = "OTG_HS_HCDMA6 (rw) register accessor: OTG_HS host channel-6 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma6`]
module"]
#[doc(alias = "OTG_HS_HCDMA6")]
pub type OtgHsHcdma6 = crate::Reg<otg_hs_hcdma6::OtgHsHcdma6Spec>;
#[doc = "OTG_HS host channel-6 DMA address register"]
pub mod otg_hs_hcdma6;
#[doc = "OTG_HS_HCDMA7 (rw) register accessor: OTG_HS host channel-7 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma7`]
module"]
#[doc(alias = "OTG_HS_HCDMA7")]
pub type OtgHsHcdma7 = crate::Reg<otg_hs_hcdma7::OtgHsHcdma7Spec>;
#[doc = "OTG_HS host channel-7 DMA address register"]
pub mod otg_hs_hcdma7;
#[doc = "OTG_HS_HCDMA8 (rw) register accessor: OTG_HS host channel-8 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma8`]
module"]
#[doc(alias = "OTG_HS_HCDMA8")]
pub type OtgHsHcdma8 = crate::Reg<otg_hs_hcdma8::OtgHsHcdma8Spec>;
#[doc = "OTG_HS host channel-8 DMA address register"]
pub mod otg_hs_hcdma8;
#[doc = "OTG_HS_HCDMA9 (rw) register accessor: OTG_HS host channel-9 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma9`]
module"]
#[doc(alias = "OTG_HS_HCDMA9")]
pub type OtgHsHcdma9 = crate::Reg<otg_hs_hcdma9::OtgHsHcdma9Spec>;
#[doc = "OTG_HS host channel-9 DMA address register"]
pub mod otg_hs_hcdma9;
#[doc = "OTG_HS_HCDMA10 (rw) register accessor: OTG_HS host channel-10 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma10`]
module"]
#[doc(alias = "OTG_HS_HCDMA10")]
pub type OtgHsHcdma10 = crate::Reg<otg_hs_hcdma10::OtgHsHcdma10Spec>;
#[doc = "OTG_HS host channel-10 DMA address register"]
pub mod otg_hs_hcdma10;
#[doc = "OTG_HS_HCDMA11 (rw) register accessor: OTG_HS host channel-11 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma11`]
module"]
#[doc(alias = "OTG_HS_HCDMA11")]
pub type OtgHsHcdma11 = crate::Reg<otg_hs_hcdma11::OtgHsHcdma11Spec>;
#[doc = "OTG_HS host channel-11 DMA address register"]
pub mod otg_hs_hcdma11;
#[doc = "OTG_HS_HCCHAR12 (rw) register accessor: OTG_HS host channel-12 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar12`]
module"]
#[doc(alias = "OTG_HS_HCCHAR12")]
pub type OtgHsHcchar12 = crate::Reg<otg_hs_hcchar12::OtgHsHcchar12Spec>;
#[doc = "OTG_HS host channel-12 characteristics register"]
pub mod otg_hs_hcchar12;
#[doc = "OTG_HS_HCSPLT12 (rw) register accessor: OTG_HS host channel-12 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt12`]
module"]
#[doc(alias = "OTG_HS_HCSPLT12")]
pub type OtgHsHcsplt12 = crate::Reg<otg_hs_hcsplt12::OtgHsHcsplt12Spec>;
#[doc = "OTG_HS host channel-12 split control register"]
pub mod otg_hs_hcsplt12;
#[doc = "OTG_HS_HCINT12 (rw) register accessor: OTG_HS host channel-12 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint12`]
module"]
#[doc(alias = "OTG_HS_HCINT12")]
pub type OtgHsHcint12 = crate::Reg<otg_hs_hcint12::OtgHsHcint12Spec>;
#[doc = "OTG_HS host channel-12 interrupt register"]
pub mod otg_hs_hcint12;
#[doc = "OTG_HS_HCINTMSK12 (rw) register accessor: OTG_HS host channel-12 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk12`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK12")]
pub type OtgHsHcintmsk12 = crate::Reg<otg_hs_hcintmsk12::OtgHsHcintmsk12Spec>;
#[doc = "OTG_HS host channel-12 interrupt mask register"]
pub mod otg_hs_hcintmsk12;
#[doc = "OTG_HS_HCTSIZ12 (rw) register accessor: OTG_HS host channel-12 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz12`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ12")]
pub type OtgHsHctsiz12 = crate::Reg<otg_hs_hctsiz12::OtgHsHctsiz12Spec>;
#[doc = "OTG_HS host channel-12 transfer size register"]
pub mod otg_hs_hctsiz12;
#[doc = "OTG_HS_HCDMA12 (rw) register accessor: OTG_HS host channel-12 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma12`]
module"]
#[doc(alias = "OTG_HS_HCDMA12")]
pub type OtgHsHcdma12 = crate::Reg<otg_hs_hcdma12::OtgHsHcdma12Spec>;
#[doc = "OTG_HS host channel-12 DMA address register"]
pub mod otg_hs_hcdma12;
#[doc = "OTG_HS_HCCHAR13 (rw) register accessor: OTG_HS host channel-13 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar13`]
module"]
#[doc(alias = "OTG_HS_HCCHAR13")]
pub type OtgHsHcchar13 = crate::Reg<otg_hs_hcchar13::OtgHsHcchar13Spec>;
#[doc = "OTG_HS host channel-13 characteristics register"]
pub mod otg_hs_hcchar13;
#[doc = "OTG_HS_HCSPLT13 (rw) register accessor: OTG_HS host channel-13 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt13`]
module"]
#[doc(alias = "OTG_HS_HCSPLT13")]
pub type OtgHsHcsplt13 = crate::Reg<otg_hs_hcsplt13::OtgHsHcsplt13Spec>;
#[doc = "OTG_HS host channel-13 split control register"]
pub mod otg_hs_hcsplt13;
#[doc = "OTG_HS_HCINT13 (rw) register accessor: OTG_HS host channel-13 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint13`]
module"]
#[doc(alias = "OTG_HS_HCINT13")]
pub type OtgHsHcint13 = crate::Reg<otg_hs_hcint13::OtgHsHcint13Spec>;
#[doc = "OTG_HS host channel-13 interrupt register"]
pub mod otg_hs_hcint13;
#[doc = "OTG_HS_HCINTMSK13 (rw) register accessor: OTG_HS host channel-13 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk13`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK13")]
pub type OtgHsHcintmsk13 = crate::Reg<otg_hs_hcintmsk13::OtgHsHcintmsk13Spec>;
#[doc = "OTG_HS host channel-13 interrupt mask register"]
pub mod otg_hs_hcintmsk13;
#[doc = "OTG_HS_HCTSIZ13 (rw) register accessor: OTG_HS host channel-13 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz13`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ13")]
pub type OtgHsHctsiz13 = crate::Reg<otg_hs_hctsiz13::OtgHsHctsiz13Spec>;
#[doc = "OTG_HS host channel-13 transfer size register"]
pub mod otg_hs_hctsiz13;
#[doc = "OTG_HS_HCDMA13 (rw) register accessor: OTG_HS host channel-13 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma13`]
module"]
#[doc(alias = "OTG_HS_HCDMA13")]
pub type OtgHsHcdma13 = crate::Reg<otg_hs_hcdma13::OtgHsHcdma13Spec>;
#[doc = "OTG_HS host channel-13 DMA address register"]
pub mod otg_hs_hcdma13;
#[doc = "OTG_HS_HCCHAR14 (rw) register accessor: OTG_HS host channel-14 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar14`]
module"]
#[doc(alias = "OTG_HS_HCCHAR14")]
pub type OtgHsHcchar14 = crate::Reg<otg_hs_hcchar14::OtgHsHcchar14Spec>;
#[doc = "OTG_HS host channel-14 characteristics register"]
pub mod otg_hs_hcchar14;
#[doc = "OTG_HS_HCSPLT14 (rw) register accessor: OTG_HS host channel-14 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt14`]
module"]
#[doc(alias = "OTG_HS_HCSPLT14")]
pub type OtgHsHcsplt14 = crate::Reg<otg_hs_hcsplt14::OtgHsHcsplt14Spec>;
#[doc = "OTG_HS host channel-14 split control register"]
pub mod otg_hs_hcsplt14;
#[doc = "OTG_HS_HCINT14 (rw) register accessor: OTG_HS host channel-14 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint14`]
module"]
#[doc(alias = "OTG_HS_HCINT14")]
pub type OtgHsHcint14 = crate::Reg<otg_hs_hcint14::OtgHsHcint14Spec>;
#[doc = "OTG_HS host channel-14 interrupt register"]
pub mod otg_hs_hcint14;
#[doc = "OTG_HS_HCINTMSK14 (rw) register accessor: OTG_HS host channel-14 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk14`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK14")]
pub type OtgHsHcintmsk14 = crate::Reg<otg_hs_hcintmsk14::OtgHsHcintmsk14Spec>;
#[doc = "OTG_HS host channel-14 interrupt mask register"]
pub mod otg_hs_hcintmsk14;
#[doc = "OTG_HS_HCTSIZ14 (rw) register accessor: OTG_HS host channel-14 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz14`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ14")]
pub type OtgHsHctsiz14 = crate::Reg<otg_hs_hctsiz14::OtgHsHctsiz14Spec>;
#[doc = "OTG_HS host channel-14 transfer size register"]
pub mod otg_hs_hctsiz14;
#[doc = "OTG_HS_HCDMA14 (rw) register accessor: OTG_HS host channel-14 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma14`]
module"]
#[doc(alias = "OTG_HS_HCDMA14")]
pub type OtgHsHcdma14 = crate::Reg<otg_hs_hcdma14::OtgHsHcdma14Spec>;
#[doc = "OTG_HS host channel-14 DMA address register"]
pub mod otg_hs_hcdma14;
#[doc = "OTG_HS_HCCHAR15 (rw) register accessor: OTG_HS host channel-15 characteristics register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcchar15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcchar15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcchar15`]
module"]
#[doc(alias = "OTG_HS_HCCHAR15")]
pub type OtgHsHcchar15 = crate::Reg<otg_hs_hcchar15::OtgHsHcchar15Spec>;
#[doc = "OTG_HS host channel-15 characteristics register"]
pub mod otg_hs_hcchar15;
#[doc = "OTG_HS_HCSPLT15 (rw) register accessor: OTG_HS host channel-15 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcsplt15`]
module"]
#[doc(alias = "OTG_HS_HCSPLT15")]
pub type OtgHsHcsplt15 = crate::Reg<otg_hs_hcsplt15::OtgHsHcsplt15Spec>;
#[doc = "OTG_HS host channel-15 split control register"]
pub mod otg_hs_hcsplt15;
#[doc = "OTG_HS_HCINT15 (rw) register accessor: OTG_HS host channel-15 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcint15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcint15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcint15`]
module"]
#[doc(alias = "OTG_HS_HCINT15")]
pub type OtgHsHcint15 = crate::Reg<otg_hs_hcint15::OtgHsHcint15Spec>;
#[doc = "OTG_HS host channel-15 interrupt register"]
pub mod otg_hs_hcint15;
#[doc = "OTG_HS_HCINTMSK15 (rw) register accessor: OTG_HS host channel-15 interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcintmsk15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcintmsk15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcintmsk15`]
module"]
#[doc(alias = "OTG_HS_HCINTMSK15")]
pub type OtgHsHcintmsk15 = crate::Reg<otg_hs_hcintmsk15::OtgHsHcintmsk15Spec>;
#[doc = "OTG_HS host channel-15 interrupt mask register"]
pub mod otg_hs_hcintmsk15;
#[doc = "OTG_HS_HCTSIZ15 (rw) register accessor: OTG_HS host channel-15 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hctsiz15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hctsiz15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hctsiz15`]
module"]
#[doc(alias = "OTG_HS_HCTSIZ15")]
pub type OtgHsHctsiz15 = crate::Reg<otg_hs_hctsiz15::OtgHsHctsiz15Spec>;
#[doc = "OTG_HS host channel-15 transfer size register"]
pub mod otg_hs_hctsiz15;
#[doc = "OTG_HS_HCDMA15 (rw) register accessor: OTG_HS host channel-15 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcdma15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcdma15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hcdma15`]
module"]
#[doc(alias = "OTG_HS_HCDMA15")]
pub type OtgHsHcdma15 = crate::Reg<otg_hs_hcdma15::OtgHsHcdma15Spec>;
#[doc = "OTG_HS host channel-15 DMA address register"]
pub mod otg_hs_hcdma15;
