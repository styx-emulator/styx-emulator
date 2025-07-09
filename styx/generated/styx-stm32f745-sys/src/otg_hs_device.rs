// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    otg_hs_dcfg: OtgHsDcfg,
    otg_hs_dctl: OtgHsDctl,
    otg_hs_dsts: OtgHsDsts,
    _reserved3: [u8; 0x04],
    otg_hs_diepmsk: OtgHsDiepmsk,
    otg_hs_doepmsk: OtgHsDoepmsk,
    otg_hs_daint: OtgHsDaint,
    otg_hs_daintmsk: OtgHsDaintmsk,
    _reserved7: [u8; 0x08],
    otg_hs_dvbusdis: OtgHsDvbusdis,
    otg_hs_dvbuspulse: OtgHsDvbuspulse,
    otg_hs_dthrctl: OtgHsDthrctl,
    otg_hs_diepempmsk: OtgHsDiepempmsk,
    otg_hs_deachint: OtgHsDeachint,
    otg_hs_deachintmsk: OtgHsDeachintmsk,
    _reserved13: [u8; 0xc0],
    otg_hs_diepctl0: OtgHsDiepctl0,
    _reserved14: [u8; 0x04],
    otg_hs_diepint0: OtgHsDiepint0,
    _reserved15: [u8; 0x04],
    otg_hs_dieptsiz0: OtgHsDieptsiz0,
    otg_hs_diepdma1: OtgHsDiepdma1,
    otg_hs_dtxfsts0: OtgHsDtxfsts0,
    _reserved18: [u8; 0x04],
    otg_hs_diepctl1: OtgHsDiepctl1,
    _reserved19: [u8; 0x04],
    otg_hs_diepint1: OtgHsDiepint1,
    _reserved20: [u8; 0x04],
    otg_hs_dieptsiz1: OtgHsDieptsiz1,
    otg_hs_diepdma2: OtgHsDiepdma2,
    otg_hs_dtxfsts1: OtgHsDtxfsts1,
    _reserved23: [u8; 0x04],
    otg_hs_diepctl2: OtgHsDiepctl2,
    _reserved24: [u8; 0x04],
    otg_hs_diepint2: OtgHsDiepint2,
    _reserved25: [u8; 0x04],
    otg_hs_dieptsiz2: OtgHsDieptsiz2,
    otg_hs_diepdma3: OtgHsDiepdma3,
    otg_hs_dtxfsts2: OtgHsDtxfsts2,
    _reserved28: [u8; 0x04],
    otg_hs_diepctl3: OtgHsDiepctl3,
    _reserved29: [u8; 0x04],
    otg_hs_diepint3: OtgHsDiepint3,
    _reserved30: [u8; 0x04],
    otg_hs_dieptsiz3: OtgHsDieptsiz3,
    otg_hs_diepdma4: OtgHsDiepdma4,
    otg_hs_dtxfsts3: OtgHsDtxfsts3,
    _reserved33: [u8; 0x04],
    otg_hs_diepctl4: OtgHsDiepctl4,
    _reserved34: [u8; 0x04],
    otg_hs_diepint4: OtgHsDiepint4,
    _reserved35: [u8; 0x04],
    otg_hs_dieptsiz4: OtgHsDieptsiz4,
    otg_hs_diepdma5: OtgHsDiepdma5,
    otg_hs_dtxfsts4: OtgHsDtxfsts4,
    _reserved38: [u8; 0x04],
    _reserved_38_otg_hs: [u8; 0x04],
    otg_hs_dtxfsts6: OtgHsDtxfsts6,
    _reserved_40_otg_hs: [u8; 0x04],
    otg_hs_dtxfsts7: OtgHsDtxfsts7,
    otg_hs_dieptsiz5: OtgHsDieptsiz5,
    _reserved43: [u8; 0x04],
    otg_hs_dtxfsts5: OtgHsDtxfsts5,
    _reserved44: [u8; 0x04],
    otg_hs_diepctl6: OtgHsDiepctl6,
    _reserved45: [u8; 0x04],
    otg_hs_diepint6: OtgHsDiepint6,
    _reserved46: [u8; 0x14],
    otg_hs_diepctl7: OtgHsDiepctl7,
    _reserved47: [u8; 0x04],
    otg_hs_diepint7: OtgHsDiepint7,
    _reserved48: [u8; 0x0114],
    otg_hs_doepctl0: OtgHsDoepctl0,
    _reserved49: [u8; 0x04],
    otg_hs_doepint0: OtgHsDoepint0,
    _reserved50: [u8; 0x04],
    otg_hs_doeptsiz0: OtgHsDoeptsiz0,
    _reserved51: [u8; 0x0c],
    otg_hs_doepctl1: OtgHsDoepctl1,
    _reserved52: [u8; 0x04],
    otg_hs_doepint1: OtgHsDoepint1,
    _reserved53: [u8; 0x04],
    otg_hs_doeptsiz1: OtgHsDoeptsiz1,
    _reserved54: [u8; 0x0c],
    otg_hs_doepctl2: OtgHsDoepctl2,
    _reserved55: [u8; 0x04],
    otg_hs_doepint2: OtgHsDoepint2,
    _reserved56: [u8; 0x04],
    otg_hs_doeptsiz2: OtgHsDoeptsiz2,
    _reserved57: [u8; 0x0c],
    otg_hs_doepctl3: OtgHsDoepctl3,
    _reserved58: [u8; 0x04],
    otg_hs_doepint3: OtgHsDoepint3,
    _reserved59: [u8; 0x04],
    otg_hs_doeptsiz3: OtgHsDoeptsiz3,
    _reserved60: [u8; 0x0c],
    otg_hs_doepctl4: OtgHsDoepctl4,
    _reserved61: [u8; 0x04],
    otg_hs_doepint4: OtgHsDoepint4,
    _reserved62: [u8; 0x04],
    otg_hs_doeptsiz4: OtgHsDoeptsiz4,
    _reserved63: [u8; 0x0c],
    otg_hs_doepctl5: OtgHsDoepctl5,
    _reserved64: [u8; 0x04],
    otg_hs_doepint5: OtgHsDoepint5,
    _reserved65: [u8; 0x04],
    otg_hs_doeptsiz5: OtgHsDoeptsiz5,
    _reserved66: [u8; 0x0c],
    otg_hs_doepctl6: OtgHsDoepctl6,
    _reserved67: [u8; 0x04],
    otg_hs_doepint6: OtgHsDoepint6,
    _reserved68: [u8; 0x04],
    otg_hs_doeptsiz6: OtgHsDoeptsiz6,
    _reserved69: [u8; 0x0c],
    otg_hs_doepctl7: OtgHsDoepctl7,
    _reserved70: [u8; 0x04],
    otg_hs_doepint7: OtgHsDoepint7,
    _reserved71: [u8; 0x04],
    otg_hs_doeptsiz7: OtgHsDoeptsiz7,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_HS device configuration register"]
    #[inline(always)]
    pub const fn otg_hs_dcfg(&self) -> &OtgHsDcfg {
        &self.otg_hs_dcfg
    }
    #[doc = "0x04 - OTG_HS device control register"]
    #[inline(always)]
    pub const fn otg_hs_dctl(&self) -> &OtgHsDctl {
        &self.otg_hs_dctl
    }
    #[doc = "0x08 - OTG_HS device status register"]
    #[inline(always)]
    pub const fn otg_hs_dsts(&self) -> &OtgHsDsts {
        &self.otg_hs_dsts
    }
    #[doc = "0x10 - OTG_HS device IN endpoint common interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_diepmsk(&self) -> &OtgHsDiepmsk {
        &self.otg_hs_diepmsk
    }
    #[doc = "0x14 - OTG_HS device OUT endpoint common interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_doepmsk(&self) -> &OtgHsDoepmsk {
        &self.otg_hs_doepmsk
    }
    #[doc = "0x18 - OTG_HS device all endpoints interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_daint(&self) -> &OtgHsDaint {
        &self.otg_hs_daint
    }
    #[doc = "0x1c - OTG_HS all endpoints interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_daintmsk(&self) -> &OtgHsDaintmsk {
        &self.otg_hs_daintmsk
    }
    #[doc = "0x28 - OTG_HS device VBUS discharge time register"]
    #[inline(always)]
    pub const fn otg_hs_dvbusdis(&self) -> &OtgHsDvbusdis {
        &self.otg_hs_dvbusdis
    }
    #[doc = "0x2c - OTG_HS device VBUS pulsing time register"]
    #[inline(always)]
    pub const fn otg_hs_dvbuspulse(&self) -> &OtgHsDvbuspulse {
        &self.otg_hs_dvbuspulse
    }
    #[doc = "0x30 - OTG_HS Device threshold control register"]
    #[inline(always)]
    pub const fn otg_hs_dthrctl(&self) -> &OtgHsDthrctl {
        &self.otg_hs_dthrctl
    }
    #[doc = "0x34 - OTG_HS device IN endpoint FIFO empty interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_diepempmsk(&self) -> &OtgHsDiepempmsk {
        &self.otg_hs_diepempmsk
    }
    #[doc = "0x38 - OTG_HS device each endpoint interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_deachint(&self) -> &OtgHsDeachint {
        &self.otg_hs_deachint
    }
    #[doc = "0x3c - OTG_HS device each endpoint interrupt register mask"]
    #[inline(always)]
    pub const fn otg_hs_deachintmsk(&self) -> &OtgHsDeachintmsk {
        &self.otg_hs_deachintmsk
    }
    #[doc = "0x100 - OTG device endpoint-0 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl0(&self) -> &OtgHsDiepctl0 {
        &self.otg_hs_diepctl0
    }
    #[doc = "0x108 - OTG device endpoint-0 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint0(&self) -> &OtgHsDiepint0 {
        &self.otg_hs_diepint0
    }
    #[doc = "0x110 - OTG_HS device IN endpoint 0 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz0(&self) -> &OtgHsDieptsiz0 {
        &self.otg_hs_dieptsiz0
    }
    #[doc = "0x114 - OTG_HS device endpoint-1 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_diepdma1(&self) -> &OtgHsDiepdma1 {
        &self.otg_hs_diepdma1
    }
    #[doc = "0x118 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts0(&self) -> &OtgHsDtxfsts0 {
        &self.otg_hs_dtxfsts0
    }
    #[doc = "0x120 - OTG device endpoint-1 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl1(&self) -> &OtgHsDiepctl1 {
        &self.otg_hs_diepctl1
    }
    #[doc = "0x128 - OTG device endpoint-1 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint1(&self) -> &OtgHsDiepint1 {
        &self.otg_hs_diepint1
    }
    #[doc = "0x130 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz1(&self) -> &OtgHsDieptsiz1 {
        &self.otg_hs_dieptsiz1
    }
    #[doc = "0x134 - OTG_HS device endpoint-2 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_diepdma2(&self) -> &OtgHsDiepdma2 {
        &self.otg_hs_diepdma2
    }
    #[doc = "0x138 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts1(&self) -> &OtgHsDtxfsts1 {
        &self.otg_hs_dtxfsts1
    }
    #[doc = "0x140 - OTG device endpoint-2 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl2(&self) -> &OtgHsDiepctl2 {
        &self.otg_hs_diepctl2
    }
    #[doc = "0x148 - OTG device endpoint-2 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint2(&self) -> &OtgHsDiepint2 {
        &self.otg_hs_diepint2
    }
    #[doc = "0x150 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz2(&self) -> &OtgHsDieptsiz2 {
        &self.otg_hs_dieptsiz2
    }
    #[doc = "0x154 - OTG_HS device endpoint-3 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_diepdma3(&self) -> &OtgHsDiepdma3 {
        &self.otg_hs_diepdma3
    }
    #[doc = "0x158 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts2(&self) -> &OtgHsDtxfsts2 {
        &self.otg_hs_dtxfsts2
    }
    #[doc = "0x160 - OTG device endpoint-3 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl3(&self) -> &OtgHsDiepctl3 {
        &self.otg_hs_diepctl3
    }
    #[doc = "0x168 - OTG device endpoint-3 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint3(&self) -> &OtgHsDiepint3 {
        &self.otg_hs_diepint3
    }
    #[doc = "0x170 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz3(&self) -> &OtgHsDieptsiz3 {
        &self.otg_hs_dieptsiz3
    }
    #[doc = "0x174 - OTG_HS device endpoint-4 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_diepdma4(&self) -> &OtgHsDiepdma4 {
        &self.otg_hs_diepdma4
    }
    #[doc = "0x178 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts3(&self) -> &OtgHsDtxfsts3 {
        &self.otg_hs_dtxfsts3
    }
    #[doc = "0x180 - OTG device endpoint-4 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl4(&self) -> &OtgHsDiepctl4 {
        &self.otg_hs_diepctl4
    }
    #[doc = "0x188 - OTG device endpoint-4 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint4(&self) -> &OtgHsDiepint4 {
        &self.otg_hs_diepint4
    }
    #[doc = "0x190 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz4(&self) -> &OtgHsDieptsiz4 {
        &self.otg_hs_dieptsiz4
    }
    #[doc = "0x194 - OTG_HS device endpoint-5 DMA address register"]
    #[inline(always)]
    pub const fn otg_hs_diepdma5(&self) -> &OtgHsDiepdma5 {
        &self.otg_hs_diepdma5
    }
    #[doc = "0x198 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts4(&self) -> &OtgHsDtxfsts4 {
        &self.otg_hs_dtxfsts4
    }
    #[doc = "0x1a0 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz6(&self) -> &OtgHsDieptsiz6 {
        unsafe { &*(self as *const Self).cast::<u8>().add(416).cast() }
    }
    #[doc = "0x1a0 - OTG device endpoint-5 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl5(&self) -> &OtgHsDiepctl5 {
        unsafe { &*(self as *const Self).cast::<u8>().add(416).cast() }
    }
    #[doc = "0x1a4 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts6(&self) -> &OtgHsDtxfsts6 {
        &self.otg_hs_dtxfsts6
    }
    #[doc = "0x1a8 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz7(&self) -> &OtgHsDieptsiz7 {
        unsafe { &*(self as *const Self).cast::<u8>().add(424).cast() }
    }
    #[doc = "0x1a8 - OTG device endpoint-5 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint5(&self) -> &OtgHsDiepint5 {
        unsafe { &*(self as *const Self).cast::<u8>().add(424).cast() }
    }
    #[doc = "0x1ac - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts7(&self) -> &OtgHsDtxfsts7 {
        &self.otg_hs_dtxfsts7
    }
    #[doc = "0x1b0 - OTG_HS device endpoint transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptsiz5(&self) -> &OtgHsDieptsiz5 {
        &self.otg_hs_dieptsiz5
    }
    #[doc = "0x1b8 - OTG_HS device IN endpoint transmit FIFO status register"]
    #[inline(always)]
    pub const fn otg_hs_dtxfsts5(&self) -> &OtgHsDtxfsts5 {
        &self.otg_hs_dtxfsts5
    }
    #[doc = "0x1c0 - OTG device endpoint-6 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl6(&self) -> &OtgHsDiepctl6 {
        &self.otg_hs_diepctl6
    }
    #[doc = "0x1c8 - OTG device endpoint-6 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint6(&self) -> &OtgHsDiepint6 {
        &self.otg_hs_diepint6
    }
    #[doc = "0x1e0 - OTG device endpoint-7 control register"]
    #[inline(always)]
    pub const fn otg_hs_diepctl7(&self) -> &OtgHsDiepctl7 {
        &self.otg_hs_diepctl7
    }
    #[doc = "0x1e8 - OTG device endpoint-7 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_diepint7(&self) -> &OtgHsDiepint7 {
        &self.otg_hs_diepint7
    }
    #[doc = "0x300 - OTG_HS device control OUT endpoint 0 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl0(&self) -> &OtgHsDoepctl0 {
        &self.otg_hs_doepctl0
    }
    #[doc = "0x308 - OTG_HS device endpoint-0 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint0(&self) -> &OtgHsDoepint0 {
        &self.otg_hs_doepint0
    }
    #[doc = "0x310 - OTG_HS device endpoint-0 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz0(&self) -> &OtgHsDoeptsiz0 {
        &self.otg_hs_doeptsiz0
    }
    #[doc = "0x320 - OTG device endpoint-1 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl1(&self) -> &OtgHsDoepctl1 {
        &self.otg_hs_doepctl1
    }
    #[doc = "0x328 - OTG_HS device endpoint-1 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint1(&self) -> &OtgHsDoepint1 {
        &self.otg_hs_doepint1
    }
    #[doc = "0x330 - OTG_HS device endpoint-1 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz1(&self) -> &OtgHsDoeptsiz1 {
        &self.otg_hs_doeptsiz1
    }
    #[doc = "0x340 - OTG device endpoint-2 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl2(&self) -> &OtgHsDoepctl2 {
        &self.otg_hs_doepctl2
    }
    #[doc = "0x348 - OTG_HS device endpoint-2 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint2(&self) -> &OtgHsDoepint2 {
        &self.otg_hs_doepint2
    }
    #[doc = "0x350 - OTG_HS device endpoint-2 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz2(&self) -> &OtgHsDoeptsiz2 {
        &self.otg_hs_doeptsiz2
    }
    #[doc = "0x360 - OTG device endpoint-3 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl3(&self) -> &OtgHsDoepctl3 {
        &self.otg_hs_doepctl3
    }
    #[doc = "0x368 - OTG_HS device endpoint-3 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint3(&self) -> &OtgHsDoepint3 {
        &self.otg_hs_doepint3
    }
    #[doc = "0x370 - OTG_HS device endpoint-3 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz3(&self) -> &OtgHsDoeptsiz3 {
        &self.otg_hs_doeptsiz3
    }
    #[doc = "0x380 - OTG device endpoint-4 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl4(&self) -> &OtgHsDoepctl4 {
        &self.otg_hs_doepctl4
    }
    #[doc = "0x388 - OTG_HS device endpoint-4 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint4(&self) -> &OtgHsDoepint4 {
        &self.otg_hs_doepint4
    }
    #[doc = "0x390 - OTG_HS device endpoint-4 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz4(&self) -> &OtgHsDoeptsiz4 {
        &self.otg_hs_doeptsiz4
    }
    #[doc = "0x3a0 - OTG device endpoint-5 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl5(&self) -> &OtgHsDoepctl5 {
        &self.otg_hs_doepctl5
    }
    #[doc = "0x3a8 - OTG_HS device endpoint-5 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint5(&self) -> &OtgHsDoepint5 {
        &self.otg_hs_doepint5
    }
    #[doc = "0x3b0 - OTG_HS device endpoint-5 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz5(&self) -> &OtgHsDoeptsiz5 {
        &self.otg_hs_doeptsiz5
    }
    #[doc = "0x3c0 - OTG device endpoint-6 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl6(&self) -> &OtgHsDoepctl6 {
        &self.otg_hs_doepctl6
    }
    #[doc = "0x3c8 - OTG_HS device endpoint-6 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint6(&self) -> &OtgHsDoepint6 {
        &self.otg_hs_doepint6
    }
    #[doc = "0x3d0 - OTG_HS device endpoint-6 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz6(&self) -> &OtgHsDoeptsiz6 {
        &self.otg_hs_doeptsiz6
    }
    #[doc = "0x3e0 - OTG device endpoint-7 control register"]
    #[inline(always)]
    pub const fn otg_hs_doepctl7(&self) -> &OtgHsDoepctl7 {
        &self.otg_hs_doepctl7
    }
    #[doc = "0x3e8 - OTG_HS device endpoint-7 interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_doepint7(&self) -> &OtgHsDoepint7 {
        &self.otg_hs_doepint7
    }
    #[doc = "0x3f0 - OTG_HS device endpoint-7 transfer size register"]
    #[inline(always)]
    pub const fn otg_hs_doeptsiz7(&self) -> &OtgHsDoeptsiz7 {
        &self.otg_hs_doeptsiz7
    }
}
#[doc = "OTG_HS_DCFG (rw) register accessor: OTG_HS device configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dcfg`]
module"]
#[doc(alias = "OTG_HS_DCFG")]
pub type OtgHsDcfg = crate::Reg<otg_hs_dcfg::OtgHsDcfgSpec>;
#[doc = "OTG_HS device configuration register"]
pub mod otg_hs_dcfg;
#[doc = "OTG_HS_DCTL (rw) register accessor: OTG_HS device control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dctl`]
module"]
#[doc(alias = "OTG_HS_DCTL")]
pub type OtgHsDctl = crate::Reg<otg_hs_dctl::OtgHsDctlSpec>;
#[doc = "OTG_HS device control register"]
pub mod otg_hs_dctl;
#[doc = "OTG_HS_DSTS (r) register accessor: OTG_HS device status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dsts`]
module"]
#[doc(alias = "OTG_HS_DSTS")]
pub type OtgHsDsts = crate::Reg<otg_hs_dsts::OtgHsDstsSpec>;
#[doc = "OTG_HS device status register"]
pub mod otg_hs_dsts;
#[doc = "OTG_HS_DIEPMSK (rw) register accessor: OTG_HS device IN endpoint common interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepmsk`]
module"]
#[doc(alias = "OTG_HS_DIEPMSK")]
pub type OtgHsDiepmsk = crate::Reg<otg_hs_diepmsk::OtgHsDiepmskSpec>;
#[doc = "OTG_HS device IN endpoint common interrupt mask register"]
pub mod otg_hs_diepmsk;
#[doc = "OTG_HS_DOEPMSK (rw) register accessor: OTG_HS device OUT endpoint common interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepmsk`]
module"]
#[doc(alias = "OTG_HS_DOEPMSK")]
pub type OtgHsDoepmsk = crate::Reg<otg_hs_doepmsk::OtgHsDoepmskSpec>;
#[doc = "OTG_HS device OUT endpoint common interrupt mask register"]
pub mod otg_hs_doepmsk;
#[doc = "OTG_HS_DAINT (r) register accessor: OTG_HS device all endpoints interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_daint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_daint`]
module"]
#[doc(alias = "OTG_HS_DAINT")]
pub type OtgHsDaint = crate::Reg<otg_hs_daint::OtgHsDaintSpec>;
#[doc = "OTG_HS device all endpoints interrupt register"]
pub mod otg_hs_daint;
#[doc = "OTG_HS_DAINTMSK (rw) register accessor: OTG_HS all endpoints interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_daintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_daintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_daintmsk`]
module"]
#[doc(alias = "OTG_HS_DAINTMSK")]
pub type OtgHsDaintmsk = crate::Reg<otg_hs_daintmsk::OtgHsDaintmskSpec>;
#[doc = "OTG_HS all endpoints interrupt mask register"]
pub mod otg_hs_daintmsk;
#[doc = "OTG_HS_DVBUSDIS (rw) register accessor: OTG_HS device VBUS discharge time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dvbusdis::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dvbusdis::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dvbusdis`]
module"]
#[doc(alias = "OTG_HS_DVBUSDIS")]
pub type OtgHsDvbusdis = crate::Reg<otg_hs_dvbusdis::OtgHsDvbusdisSpec>;
#[doc = "OTG_HS device VBUS discharge time register"]
pub mod otg_hs_dvbusdis;
#[doc = "OTG_HS_DVBUSPULSE (rw) register accessor: OTG_HS device VBUS pulsing time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dvbuspulse::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dvbuspulse::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dvbuspulse`]
module"]
#[doc(alias = "OTG_HS_DVBUSPULSE")]
pub type OtgHsDvbuspulse = crate::Reg<otg_hs_dvbuspulse::OtgHsDvbuspulseSpec>;
#[doc = "OTG_HS device VBUS pulsing time register"]
pub mod otg_hs_dvbuspulse;
#[doc = "OTG_HS_DTHRCTL (rw) register accessor: OTG_HS Device threshold control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dthrctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dthrctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dthrctl`]
module"]
#[doc(alias = "OTG_HS_DTHRCTL")]
pub type OtgHsDthrctl = crate::Reg<otg_hs_dthrctl::OtgHsDthrctlSpec>;
#[doc = "OTG_HS Device threshold control register"]
pub mod otg_hs_dthrctl;
#[doc = "OTG_HS_DIEPEMPMSK (rw) register accessor: OTG_HS device IN endpoint FIFO empty interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepempmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepempmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepempmsk`]
module"]
#[doc(alias = "OTG_HS_DIEPEMPMSK")]
pub type OtgHsDiepempmsk = crate::Reg<otg_hs_diepempmsk::OtgHsDiepempmskSpec>;
#[doc = "OTG_HS device IN endpoint FIFO empty interrupt mask register"]
pub mod otg_hs_diepempmsk;
#[doc = "OTG_HS_DEACHINT (rw) register accessor: OTG_HS device each endpoint interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_deachint::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_deachint::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_deachint`]
module"]
#[doc(alias = "OTG_HS_DEACHINT")]
pub type OtgHsDeachint = crate::Reg<otg_hs_deachint::OtgHsDeachintSpec>;
#[doc = "OTG_HS device each endpoint interrupt register"]
pub mod otg_hs_deachint;
#[doc = "OTG_HS_DEACHINTMSK (rw) register accessor: OTG_HS device each endpoint interrupt register mask\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_deachintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_deachintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_deachintmsk`]
module"]
#[doc(alias = "OTG_HS_DEACHINTMSK")]
pub type OtgHsDeachintmsk = crate::Reg<otg_hs_deachintmsk::OtgHsDeachintmskSpec>;
#[doc = "OTG_HS device each endpoint interrupt register mask"]
pub mod otg_hs_deachintmsk;
#[doc = "OTG_HS_DIEPCTL0 (rw) register accessor: OTG device endpoint-0 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl0`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL0")]
pub type OtgHsDiepctl0 = crate::Reg<otg_hs_diepctl0::OtgHsDiepctl0Spec>;
#[doc = "OTG device endpoint-0 control register"]
pub mod otg_hs_diepctl0;
#[doc = "OTG_HS_DIEPCTL1 (rw) register accessor: OTG device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl1`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL1")]
pub type OtgHsDiepctl1 = crate::Reg<otg_hs_diepctl1::OtgHsDiepctl1Spec>;
#[doc = "OTG device endpoint-1 control register"]
pub mod otg_hs_diepctl1;
#[doc = "OTG_HS_DIEPCTL2 (rw) register accessor: OTG device endpoint-2 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl2`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL2")]
pub type OtgHsDiepctl2 = crate::Reg<otg_hs_diepctl2::OtgHsDiepctl2Spec>;
#[doc = "OTG device endpoint-2 control register"]
pub mod otg_hs_diepctl2;
#[doc = "OTG_HS_DIEPCTL3 (rw) register accessor: OTG device endpoint-3 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl3`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL3")]
pub type OtgHsDiepctl3 = crate::Reg<otg_hs_diepctl3::OtgHsDiepctl3Spec>;
#[doc = "OTG device endpoint-3 control register"]
pub mod otg_hs_diepctl3;
#[doc = "OTG_HS_DIEPCTL4 (rw) register accessor: OTG device endpoint-4 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl4`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL4")]
pub type OtgHsDiepctl4 = crate::Reg<otg_hs_diepctl4::OtgHsDiepctl4Spec>;
#[doc = "OTG device endpoint-4 control register"]
pub mod otg_hs_diepctl4;
#[doc = "OTG_HS_DIEPCTL5 (rw) register accessor: OTG device endpoint-5 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl5`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL5")]
pub type OtgHsDiepctl5 = crate::Reg<otg_hs_diepctl5::OtgHsDiepctl5Spec>;
#[doc = "OTG device endpoint-5 control register"]
pub mod otg_hs_diepctl5;
#[doc = "OTG_HS_DIEPCTL6 (rw) register accessor: OTG device endpoint-6 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl6`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL6")]
pub type OtgHsDiepctl6 = crate::Reg<otg_hs_diepctl6::OtgHsDiepctl6Spec>;
#[doc = "OTG device endpoint-6 control register"]
pub mod otg_hs_diepctl6;
#[doc = "OTG_HS_DIEPCTL7 (rw) register accessor: OTG device endpoint-7 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepctl7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepctl7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepctl7`]
module"]
#[doc(alias = "OTG_HS_DIEPCTL7")]
pub type OtgHsDiepctl7 = crate::Reg<otg_hs_diepctl7::OtgHsDiepctl7Spec>;
#[doc = "OTG device endpoint-7 control register"]
pub mod otg_hs_diepctl7;
#[doc = "OTG_HS_DIEPINT0 (rw) register accessor: OTG device endpoint-0 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint0`]
module"]
#[doc(alias = "OTG_HS_DIEPINT0")]
pub type OtgHsDiepint0 = crate::Reg<otg_hs_diepint0::OtgHsDiepint0Spec>;
#[doc = "OTG device endpoint-0 interrupt register"]
pub mod otg_hs_diepint0;
#[doc = "OTG_HS_DIEPINT1 (rw) register accessor: OTG device endpoint-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint1`]
module"]
#[doc(alias = "OTG_HS_DIEPINT1")]
pub type OtgHsDiepint1 = crate::Reg<otg_hs_diepint1::OtgHsDiepint1Spec>;
#[doc = "OTG device endpoint-1 interrupt register"]
pub mod otg_hs_diepint1;
#[doc = "OTG_HS_DIEPINT2 (rw) register accessor: OTG device endpoint-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint2`]
module"]
#[doc(alias = "OTG_HS_DIEPINT2")]
pub type OtgHsDiepint2 = crate::Reg<otg_hs_diepint2::OtgHsDiepint2Spec>;
#[doc = "OTG device endpoint-2 interrupt register"]
pub mod otg_hs_diepint2;
#[doc = "OTG_HS_DIEPINT3 (rw) register accessor: OTG device endpoint-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint3`]
module"]
#[doc(alias = "OTG_HS_DIEPINT3")]
pub type OtgHsDiepint3 = crate::Reg<otg_hs_diepint3::OtgHsDiepint3Spec>;
#[doc = "OTG device endpoint-3 interrupt register"]
pub mod otg_hs_diepint3;
#[doc = "OTG_HS_DIEPINT4 (rw) register accessor: OTG device endpoint-4 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint4`]
module"]
#[doc(alias = "OTG_HS_DIEPINT4")]
pub type OtgHsDiepint4 = crate::Reg<otg_hs_diepint4::OtgHsDiepint4Spec>;
#[doc = "OTG device endpoint-4 interrupt register"]
pub mod otg_hs_diepint4;
#[doc = "OTG_HS_DIEPINT5 (rw) register accessor: OTG device endpoint-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint5`]
module"]
#[doc(alias = "OTG_HS_DIEPINT5")]
pub type OtgHsDiepint5 = crate::Reg<otg_hs_diepint5::OtgHsDiepint5Spec>;
#[doc = "OTG device endpoint-5 interrupt register"]
pub mod otg_hs_diepint5;
#[doc = "OTG_HS_DIEPINT6 (rw) register accessor: OTG device endpoint-6 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint6`]
module"]
#[doc(alias = "OTG_HS_DIEPINT6")]
pub type OtgHsDiepint6 = crate::Reg<otg_hs_diepint6::OtgHsDiepint6Spec>;
#[doc = "OTG device endpoint-6 interrupt register"]
pub mod otg_hs_diepint6;
#[doc = "OTG_HS_DIEPINT7 (rw) register accessor: OTG device endpoint-7 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepint7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepint7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepint7`]
module"]
#[doc(alias = "OTG_HS_DIEPINT7")]
pub type OtgHsDiepint7 = crate::Reg<otg_hs_diepint7::OtgHsDiepint7Spec>;
#[doc = "OTG device endpoint-7 interrupt register"]
pub mod otg_hs_diepint7;
#[doc = "OTG_HS_DIEPTSIZ0 (rw) register accessor: OTG_HS device IN endpoint 0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz0`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ0")]
pub type OtgHsDieptsiz0 = crate::Reg<otg_hs_dieptsiz0::OtgHsDieptsiz0Spec>;
#[doc = "OTG_HS device IN endpoint 0 transfer size register"]
pub mod otg_hs_dieptsiz0;
#[doc = "OTG_HS_DIEPDMA1 (rw) register accessor: OTG_HS device endpoint-1 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepdma1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepdma1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepdma1`]
module"]
#[doc(alias = "OTG_HS_DIEPDMA1")]
pub type OtgHsDiepdma1 = crate::Reg<otg_hs_diepdma1::OtgHsDiepdma1Spec>;
#[doc = "OTG_HS device endpoint-1 DMA address register"]
pub mod otg_hs_diepdma1;
#[doc = "OTG_HS_DIEPDMA2 (rw) register accessor: OTG_HS device endpoint-2 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepdma2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepdma2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepdma2`]
module"]
#[doc(alias = "OTG_HS_DIEPDMA2")]
pub type OtgHsDiepdma2 = crate::Reg<otg_hs_diepdma2::OtgHsDiepdma2Spec>;
#[doc = "OTG_HS device endpoint-2 DMA address register"]
pub mod otg_hs_diepdma2;
#[doc = "OTG_HS_DIEPDMA3 (rw) register accessor: OTG_HS device endpoint-3 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepdma3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepdma3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepdma3`]
module"]
#[doc(alias = "OTG_HS_DIEPDMA3")]
pub type OtgHsDiepdma3 = crate::Reg<otg_hs_diepdma3::OtgHsDiepdma3Spec>;
#[doc = "OTG_HS device endpoint-3 DMA address register"]
pub mod otg_hs_diepdma3;
#[doc = "OTG_HS_DIEPDMA4 (rw) register accessor: OTG_HS device endpoint-4 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepdma4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepdma4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepdma4`]
module"]
#[doc(alias = "OTG_HS_DIEPDMA4")]
pub type OtgHsDiepdma4 = crate::Reg<otg_hs_diepdma4::OtgHsDiepdma4Spec>;
#[doc = "OTG_HS device endpoint-4 DMA address register"]
pub mod otg_hs_diepdma4;
#[doc = "OTG_HS_DIEPDMA5 (rw) register accessor: OTG_HS device endpoint-5 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepdma5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepdma5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_diepdma5`]
module"]
#[doc(alias = "OTG_HS_DIEPDMA5")]
pub type OtgHsDiepdma5 = crate::Reg<otg_hs_diepdma5::OtgHsDiepdma5Spec>;
#[doc = "OTG_HS device endpoint-5 DMA address register"]
pub mod otg_hs_diepdma5;
#[doc = "OTG_HS_DTXFSTS0 (r) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts0`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS0")]
pub type OtgHsDtxfsts0 = crate::Reg<otg_hs_dtxfsts0::OtgHsDtxfsts0Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts0;
#[doc = "OTG_HS_DTXFSTS1 (r) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts1`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS1")]
pub type OtgHsDtxfsts1 = crate::Reg<otg_hs_dtxfsts1::OtgHsDtxfsts1Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts1;
#[doc = "OTG_HS_DTXFSTS2 (r) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts2`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS2")]
pub type OtgHsDtxfsts2 = crate::Reg<otg_hs_dtxfsts2::OtgHsDtxfsts2Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts2;
#[doc = "OTG_HS_DTXFSTS3 (r) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts3`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS3")]
pub type OtgHsDtxfsts3 = crate::Reg<otg_hs_dtxfsts3::OtgHsDtxfsts3Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts3;
#[doc = "OTG_HS_DTXFSTS4 (r) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts4`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS4")]
pub type OtgHsDtxfsts4 = crate::Reg<otg_hs_dtxfsts4::OtgHsDtxfsts4Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts4;
#[doc = "OTG_HS_DTXFSTS5 (r) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts5`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS5")]
pub type OtgHsDtxfsts5 = crate::Reg<otg_hs_dtxfsts5::OtgHsDtxfsts5Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts5;
#[doc = "OTG_HS_DIEPTSIZ1 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz1`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ1")]
pub type OtgHsDieptsiz1 = crate::Reg<otg_hs_dieptsiz1::OtgHsDieptsiz1Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz1;
#[doc = "OTG_HS_DIEPTSIZ2 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz2`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ2")]
pub type OtgHsDieptsiz2 = crate::Reg<otg_hs_dieptsiz2::OtgHsDieptsiz2Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz2;
#[doc = "OTG_HS_DIEPTSIZ3 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz3`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ3")]
pub type OtgHsDieptsiz3 = crate::Reg<otg_hs_dieptsiz3::OtgHsDieptsiz3Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz3;
#[doc = "OTG_HS_DIEPTSIZ4 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz4`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ4")]
pub type OtgHsDieptsiz4 = crate::Reg<otg_hs_dieptsiz4::OtgHsDieptsiz4Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz4;
#[doc = "OTG_HS_DIEPTSIZ5 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz5`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ5")]
pub type OtgHsDieptsiz5 = crate::Reg<otg_hs_dieptsiz5::OtgHsDieptsiz5Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz5;
#[doc = "OTG_HS_DOEPCTL0 (rw) register accessor: OTG_HS device control OUT endpoint 0 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl0`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL0")]
pub type OtgHsDoepctl0 = crate::Reg<otg_hs_doepctl0::OtgHsDoepctl0Spec>;
#[doc = "OTG_HS device control OUT endpoint 0 control register"]
pub mod otg_hs_doepctl0;
#[doc = "OTG_HS_DOEPCTL1 (rw) register accessor: OTG device endpoint-1 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl1`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL1")]
pub type OtgHsDoepctl1 = crate::Reg<otg_hs_doepctl1::OtgHsDoepctl1Spec>;
#[doc = "OTG device endpoint-1 control register"]
pub mod otg_hs_doepctl1;
#[doc = "OTG_HS_DOEPCTL2 (rw) register accessor: OTG device endpoint-2 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl2`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL2")]
pub type OtgHsDoepctl2 = crate::Reg<otg_hs_doepctl2::OtgHsDoepctl2Spec>;
#[doc = "OTG device endpoint-2 control register"]
pub mod otg_hs_doepctl2;
#[doc = "OTG_HS_DOEPCTL3 (rw) register accessor: OTG device endpoint-3 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl3`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL3")]
pub type OtgHsDoepctl3 = crate::Reg<otg_hs_doepctl3::OtgHsDoepctl3Spec>;
#[doc = "OTG device endpoint-3 control register"]
pub mod otg_hs_doepctl3;
#[doc = "OTG_HS_DOEPINT0 (rw) register accessor: OTG_HS device endpoint-0 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint0`]
module"]
#[doc(alias = "OTG_HS_DOEPINT0")]
pub type OtgHsDoepint0 = crate::Reg<otg_hs_doepint0::OtgHsDoepint0Spec>;
#[doc = "OTG_HS device endpoint-0 interrupt register"]
pub mod otg_hs_doepint0;
#[doc = "OTG_HS_DOEPINT1 (rw) register accessor: OTG_HS device endpoint-1 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint1`]
module"]
#[doc(alias = "OTG_HS_DOEPINT1")]
pub type OtgHsDoepint1 = crate::Reg<otg_hs_doepint1::OtgHsDoepint1Spec>;
#[doc = "OTG_HS device endpoint-1 interrupt register"]
pub mod otg_hs_doepint1;
#[doc = "OTG_HS_DOEPINT2 (rw) register accessor: OTG_HS device endpoint-2 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint2`]
module"]
#[doc(alias = "OTG_HS_DOEPINT2")]
pub type OtgHsDoepint2 = crate::Reg<otg_hs_doepint2::OtgHsDoepint2Spec>;
#[doc = "OTG_HS device endpoint-2 interrupt register"]
pub mod otg_hs_doepint2;
#[doc = "OTG_HS_DOEPINT3 (rw) register accessor: OTG_HS device endpoint-3 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint3`]
module"]
#[doc(alias = "OTG_HS_DOEPINT3")]
pub type OtgHsDoepint3 = crate::Reg<otg_hs_doepint3::OtgHsDoepint3Spec>;
#[doc = "OTG_HS device endpoint-3 interrupt register"]
pub mod otg_hs_doepint3;
#[doc = "OTG_HS_DOEPINT4 (rw) register accessor: OTG_HS device endpoint-4 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint4`]
module"]
#[doc(alias = "OTG_HS_DOEPINT4")]
pub type OtgHsDoepint4 = crate::Reg<otg_hs_doepint4::OtgHsDoepint4Spec>;
#[doc = "OTG_HS device endpoint-4 interrupt register"]
pub mod otg_hs_doepint4;
#[doc = "OTG_HS_DOEPINT5 (rw) register accessor: OTG_HS device endpoint-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint5`]
module"]
#[doc(alias = "OTG_HS_DOEPINT5")]
pub type OtgHsDoepint5 = crate::Reg<otg_hs_doepint5::OtgHsDoepint5Spec>;
#[doc = "OTG_HS device endpoint-5 interrupt register"]
pub mod otg_hs_doepint5;
#[doc = "OTG_HS_DOEPINT6 (rw) register accessor: OTG_HS device endpoint-6 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint6`]
module"]
#[doc(alias = "OTG_HS_DOEPINT6")]
pub type OtgHsDoepint6 = crate::Reg<otg_hs_doepint6::OtgHsDoepint6Spec>;
#[doc = "OTG_HS device endpoint-6 interrupt register"]
pub mod otg_hs_doepint6;
#[doc = "OTG_HS_DOEPINT7 (rw) register accessor: OTG_HS device endpoint-7 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepint7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepint7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepint7`]
module"]
#[doc(alias = "OTG_HS_DOEPINT7")]
pub type OtgHsDoepint7 = crate::Reg<otg_hs_doepint7::OtgHsDoepint7Spec>;
#[doc = "OTG_HS device endpoint-7 interrupt register"]
pub mod otg_hs_doepint7;
#[doc = "OTG_HS_DOEPTSIZ0 (rw) register accessor: OTG_HS device endpoint-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz0`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ0")]
pub type OtgHsDoeptsiz0 = crate::Reg<otg_hs_doeptsiz0::OtgHsDoeptsiz0Spec>;
#[doc = "OTG_HS device endpoint-0 transfer size register"]
pub mod otg_hs_doeptsiz0;
#[doc = "OTG_HS_DOEPTSIZ1 (rw) register accessor: OTG_HS device endpoint-1 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz1`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ1")]
pub type OtgHsDoeptsiz1 = crate::Reg<otg_hs_doeptsiz1::OtgHsDoeptsiz1Spec>;
#[doc = "OTG_HS device endpoint-1 transfer size register"]
pub mod otg_hs_doeptsiz1;
#[doc = "OTG_HS_DOEPTSIZ2 (rw) register accessor: OTG_HS device endpoint-2 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz2`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ2")]
pub type OtgHsDoeptsiz2 = crate::Reg<otg_hs_doeptsiz2::OtgHsDoeptsiz2Spec>;
#[doc = "OTG_HS device endpoint-2 transfer size register"]
pub mod otg_hs_doeptsiz2;
#[doc = "OTG_HS_DOEPTSIZ3 (rw) register accessor: OTG_HS device endpoint-3 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz3`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ3")]
pub type OtgHsDoeptsiz3 = crate::Reg<otg_hs_doeptsiz3::OtgHsDoeptsiz3Spec>;
#[doc = "OTG_HS device endpoint-3 transfer size register"]
pub mod otg_hs_doeptsiz3;
#[doc = "OTG_HS_DOEPTSIZ4 (rw) register accessor: OTG_HS device endpoint-4 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz4`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ4")]
pub type OtgHsDoeptsiz4 = crate::Reg<otg_hs_doeptsiz4::OtgHsDoeptsiz4Spec>;
#[doc = "OTG_HS device endpoint-4 transfer size register"]
pub mod otg_hs_doeptsiz4;
#[doc = "OTG_HS_DIEPTSIZ6 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz6`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ6")]
pub type OtgHsDieptsiz6 = crate::Reg<otg_hs_dieptsiz6::OtgHsDieptsiz6Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz6;
#[doc = "OTG_HS_DTXFSTS6 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dtxfsts6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts6`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS6")]
pub type OtgHsDtxfsts6 = crate::Reg<otg_hs_dtxfsts6::OtgHsDtxfsts6Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts6;
#[doc = "OTG_HS_DIEPTSIZ7 (rw) register accessor: OTG_HS device endpoint transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptsiz7`]
module"]
#[doc(alias = "OTG_HS_DIEPTSIZ7")]
pub type OtgHsDieptsiz7 = crate::Reg<otg_hs_dieptsiz7::OtgHsDieptsiz7Spec>;
#[doc = "OTG_HS device endpoint transfer size register"]
pub mod otg_hs_dieptsiz7;
#[doc = "OTG_HS_DTXFSTS7 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dtxfsts7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dtxfsts7`]
module"]
#[doc(alias = "OTG_HS_DTXFSTS7")]
pub type OtgHsDtxfsts7 = crate::Reg<otg_hs_dtxfsts7::OtgHsDtxfsts7Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO status register"]
pub mod otg_hs_dtxfsts7;
#[doc = "OTG_HS_DOEPCTL4 (rw) register accessor: OTG device endpoint-4 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl4`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL4")]
pub type OtgHsDoepctl4 = crate::Reg<otg_hs_doepctl4::OtgHsDoepctl4Spec>;
#[doc = "OTG device endpoint-4 control register"]
pub mod otg_hs_doepctl4;
#[doc = "OTG_HS_DOEPCTL5 (rw) register accessor: OTG device endpoint-5 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl5`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL5")]
pub type OtgHsDoepctl5 = crate::Reg<otg_hs_doepctl5::OtgHsDoepctl5Spec>;
#[doc = "OTG device endpoint-5 control register"]
pub mod otg_hs_doepctl5;
#[doc = "OTG_HS_DOEPCTL6 (rw) register accessor: OTG device endpoint-6 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl6`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL6")]
pub type OtgHsDoepctl6 = crate::Reg<otg_hs_doepctl6::OtgHsDoepctl6Spec>;
#[doc = "OTG device endpoint-6 control register"]
pub mod otg_hs_doepctl6;
#[doc = "OTG_HS_DOEPCTL7 (rw) register accessor: OTG device endpoint-7 control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepctl7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepctl7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doepctl7`]
module"]
#[doc(alias = "OTG_HS_DOEPCTL7")]
pub type OtgHsDoepctl7 = crate::Reg<otg_hs_doepctl7::OtgHsDoepctl7Spec>;
#[doc = "OTG device endpoint-7 control register"]
pub mod otg_hs_doepctl7;
#[doc = "OTG_HS_DOEPTSIZ5 (rw) register accessor: OTG_HS device endpoint-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz5`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ5")]
pub type OtgHsDoeptsiz5 = crate::Reg<otg_hs_doeptsiz5::OtgHsDoeptsiz5Spec>;
#[doc = "OTG_HS device endpoint-5 transfer size register"]
pub mod otg_hs_doeptsiz5;
#[doc = "OTG_HS_DOEPTSIZ6 (rw) register accessor: OTG_HS device endpoint-6 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz6`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ6")]
pub type OtgHsDoeptsiz6 = crate::Reg<otg_hs_doeptsiz6::OtgHsDoeptsiz6Spec>;
#[doc = "OTG_HS device endpoint-6 transfer size register"]
pub mod otg_hs_doeptsiz6;
#[doc = "OTG_HS_DOEPTSIZ7 (rw) register accessor: OTG_HS device endpoint-7 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doeptsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doeptsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_doeptsiz7`]
module"]
#[doc(alias = "OTG_HS_DOEPTSIZ7")]
pub type OtgHsDoeptsiz7 = crate::Reg<otg_hs_doeptsiz7::OtgHsDoeptsiz7Spec>;
#[doc = "OTG_HS device endpoint-7 transfer size register"]
pub mod otg_hs_doeptsiz7;
