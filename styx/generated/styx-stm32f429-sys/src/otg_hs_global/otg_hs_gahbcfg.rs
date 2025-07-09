// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_GAHBCFG` reader"]
pub type R = crate::R<OtgHsGahbcfgSpec>;
#[doc = "Register `OTG_HS_GAHBCFG` writer"]
pub type W = crate::W<OtgHsGahbcfgSpec>;
#[doc = "Field `GINT` reader - Global interrupt mask"]
pub type GintR = crate::BitReader;
#[doc = "Field `GINT` writer - Global interrupt mask"]
pub type GintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HBSTLEN` reader - Burst length/type"]
pub type HbstlenR = crate::FieldReader;
#[doc = "Field `HBSTLEN` writer - Burst length/type"]
pub type HbstlenW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DMAEN` reader - DMA enable"]
pub type DmaenR = crate::BitReader;
#[doc = "Field `DMAEN` writer - DMA enable"]
pub type DmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFELVL` reader - TxFIFO empty level"]
pub type TxfelvlR = crate::BitReader;
#[doc = "Field `TXFELVL` writer - TxFIFO empty level"]
pub type TxfelvlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTXFELVL` reader - Periodic TxFIFO empty level"]
pub type PtxfelvlR = crate::BitReader;
#[doc = "Field `PTXFELVL` writer - Periodic TxFIFO empty level"]
pub type PtxfelvlW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Global interrupt mask"]
    #[inline(always)]
    pub fn gint(&self) -> GintR {
        GintR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:4 - Burst length/type"]
    #[inline(always)]
    pub fn hbstlen(&self) -> HbstlenR {
        HbstlenR::new(((self.bits >> 1) & 0x0f) as u8)
    }
    #[doc = "Bit 5 - DMA enable"]
    #[inline(always)]
    pub fn dmaen(&self) -> DmaenR {
        DmaenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 7 - TxFIFO empty level"]
    #[inline(always)]
    pub fn txfelvl(&self) -> TxfelvlR {
        TxfelvlR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Periodic TxFIFO empty level"]
    #[inline(always)]
    pub fn ptxfelvl(&self) -> PtxfelvlR {
        PtxfelvlR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Global interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn gint(&mut self) -> GintW<OtgHsGahbcfgSpec> {
        GintW::new(self, 0)
    }
    #[doc = "Bits 1:4 - Burst length/type"]
    #[inline(always)]
    #[must_use]
    pub fn hbstlen(&mut self) -> HbstlenW<OtgHsGahbcfgSpec> {
        HbstlenW::new(self, 1)
    }
    #[doc = "Bit 5 - DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen(&mut self) -> DmaenW<OtgHsGahbcfgSpec> {
        DmaenW::new(self, 5)
    }
    #[doc = "Bit 7 - TxFIFO empty level"]
    #[inline(always)]
    #[must_use]
    pub fn txfelvl(&mut self) -> TxfelvlW<OtgHsGahbcfgSpec> {
        TxfelvlW::new(self, 7)
    }
    #[doc = "Bit 8 - Periodic TxFIFO empty level"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfelvl(&mut self) -> PtxfelvlW<OtgHsGahbcfgSpec> {
        PtxfelvlW::new(self, 8)
    }
}
#[doc = "OTG_HS AHB configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gahbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gahbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsGahbcfgSpec;
impl crate::RegisterSpec for OtgHsGahbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`otg_hs_gahbcfg::R`](R) reader structure"]
impl crate::Readable for OtgHsGahbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_gahbcfg::W`](W) writer structure"]
impl crate::Writable for OtgHsGahbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_GAHBCFG to value 0"]
impl crate::Resettable for OtgHsGahbcfgSpec {
    const RESET_VALUE: u32 = 0;
}
