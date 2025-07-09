// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DIEPINT5` reader"]
pub type R = crate::R<OtgFsDiepint5Spec>;
#[doc = "Register `OTG_FS_DIEPINT5` writer"]
pub type W = crate::W<OtgFsDiepint5Spec>;
#[doc = "Field `XFRC` reader - XFRC"]
pub type XfrcR = crate::BitReader;
#[doc = "Field `XFRC` writer - XFRC"]
pub type XfrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDISD` reader - EPDISD"]
pub type EpdisdR = crate::BitReader;
#[doc = "Field `EPDISD` writer - EPDISD"]
pub type EpdisdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TOC` reader - TOC"]
pub type TocR = crate::BitReader;
#[doc = "Field `TOC` writer - TOC"]
pub type TocW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ITTXFE` reader - ITTXFE"]
pub type IttxfeR = crate::BitReader;
#[doc = "Field `ITTXFE` writer - ITTXFE"]
pub type IttxfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `INEPNE` reader - INEPNE"]
pub type InepneR = crate::BitReader;
#[doc = "Field `INEPNE` writer - INEPNE"]
pub type InepneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFE` reader - TXFE"]
pub type TxfeR = crate::BitReader;
#[doc = "Field `TXFE` writer - TXFE"]
pub type TxfeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - XFRC"]
    #[inline(always)]
    pub fn xfrc(&self) -> XfrcR {
        XfrcR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - EPDISD"]
    #[inline(always)]
    pub fn epdisd(&self) -> EpdisdR {
        EpdisdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - TOC"]
    #[inline(always)]
    pub fn toc(&self) -> TocR {
        TocR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - ITTXFE"]
    #[inline(always)]
    pub fn ittxfe(&self) -> IttxfeR {
        IttxfeR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - INEPNE"]
    #[inline(always)]
    pub fn inepne(&self) -> InepneR {
        InepneR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - TXFE"]
    #[inline(always)]
    pub fn txfe(&self) -> TxfeR {
        TxfeR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - XFRC"]
    #[inline(always)]
    #[must_use]
    pub fn xfrc(&mut self) -> XfrcW<OtgFsDiepint5Spec> {
        XfrcW::new(self, 0)
    }
    #[doc = "Bit 1 - EPDISD"]
    #[inline(always)]
    #[must_use]
    pub fn epdisd(&mut self) -> EpdisdW<OtgFsDiepint5Spec> {
        EpdisdW::new(self, 1)
    }
    #[doc = "Bit 3 - TOC"]
    #[inline(always)]
    #[must_use]
    pub fn toc(&mut self) -> TocW<OtgFsDiepint5Spec> {
        TocW::new(self, 3)
    }
    #[doc = "Bit 4 - ITTXFE"]
    #[inline(always)]
    #[must_use]
    pub fn ittxfe(&mut self) -> IttxfeW<OtgFsDiepint5Spec> {
        IttxfeW::new(self, 4)
    }
    #[doc = "Bit 6 - INEPNE"]
    #[inline(always)]
    #[must_use]
    pub fn inepne(&mut self) -> InepneW<OtgFsDiepint5Spec> {
        InepneW::new(self, 6)
    }
    #[doc = "Bit 7 - TXFE"]
    #[inline(always)]
    #[must_use]
    pub fn txfe(&mut self) -> TxfeW<OtgFsDiepint5Spec> {
        TxfeW::new(self, 7)
    }
}
#[doc = "device endpoint-5 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_diepint5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_diepint5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDiepint5Spec;
impl crate::RegisterSpec for OtgFsDiepint5Spec {
    type Ux = u32;
    const OFFSET: u64 = 424u64;
}
#[doc = "`read()` method returns [`otg_fs_diepint5::R`](R) reader structure"]
impl crate::Readable for OtgFsDiepint5Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_diepint5::W`](W) writer structure"]
impl crate::Writable for OtgFsDiepint5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DIEPINT5 to value 0"]
impl crate::Resettable for OtgFsDiepint5Spec {
    const RESET_VALUE: u32 = 0;
}
