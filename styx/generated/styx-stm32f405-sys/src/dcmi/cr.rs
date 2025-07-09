// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `CAPTURE` reader - Capture enable"]
pub type CaptureR = crate::BitReader;
#[doc = "Field `CAPTURE` writer - Capture enable"]
pub type CaptureW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CM` reader - Capture mode"]
pub type CmR = crate::BitReader;
#[doc = "Field `CM` writer - Capture mode"]
pub type CmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CROP` reader - Crop feature"]
pub type CropR = crate::BitReader;
#[doc = "Field `CROP` writer - Crop feature"]
pub type CropW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JPEG` reader - JPEG format"]
pub type JpegR = crate::BitReader;
#[doc = "Field `JPEG` writer - JPEG format"]
pub type JpegW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ESS` reader - Embedded synchronization select"]
pub type EssR = crate::BitReader;
#[doc = "Field `ESS` writer - Embedded synchronization select"]
pub type EssW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PCKPOL` reader - Pixel clock polarity"]
pub type PckpolR = crate::BitReader;
#[doc = "Field `PCKPOL` writer - Pixel clock polarity"]
pub type PckpolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSPOL` reader - Horizontal synchronization polarity"]
pub type HspolR = crate::BitReader;
#[doc = "Field `HSPOL` writer - Horizontal synchronization polarity"]
pub type HspolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSPOL` reader - Vertical synchronization polarity"]
pub type VspolR = crate::BitReader;
#[doc = "Field `VSPOL` writer - Vertical synchronization polarity"]
pub type VspolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FCRC` reader - Frame capture rate control"]
pub type FcrcR = crate::FieldReader;
#[doc = "Field `FCRC` writer - Frame capture rate control"]
pub type FcrcW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `EDM` reader - Extended data mode"]
pub type EdmR = crate::FieldReader;
#[doc = "Field `EDM` writer - Extended data mode"]
pub type EdmW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ENABLE` reader - DCMI enable"]
pub type EnableR = crate::BitReader;
#[doc = "Field `ENABLE` writer - DCMI enable"]
pub type EnableW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Capture enable"]
    #[inline(always)]
    pub fn capture(&self) -> CaptureR {
        CaptureR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Capture mode"]
    #[inline(always)]
    pub fn cm(&self) -> CmR {
        CmR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Crop feature"]
    #[inline(always)]
    pub fn crop(&self) -> CropR {
        CropR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - JPEG format"]
    #[inline(always)]
    pub fn jpeg(&self) -> JpegR {
        JpegR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Embedded synchronization select"]
    #[inline(always)]
    pub fn ess(&self) -> EssR {
        EssR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Pixel clock polarity"]
    #[inline(always)]
    pub fn pckpol(&self) -> PckpolR {
        PckpolR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Horizontal synchronization polarity"]
    #[inline(always)]
    pub fn hspol(&self) -> HspolR {
        HspolR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Vertical synchronization polarity"]
    #[inline(always)]
    pub fn vspol(&self) -> VspolR {
        VspolR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:9 - Frame capture rate control"]
    #[inline(always)]
    pub fn fcrc(&self) -> FcrcR {
        FcrcR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:11 - Extended data mode"]
    #[inline(always)]
    pub fn edm(&self) -> EdmR {
        EdmR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bit 14 - DCMI enable"]
    #[inline(always)]
    pub fn enable(&self) -> EnableR {
        EnableR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Capture enable"]
    #[inline(always)]
    #[must_use]
    pub fn capture(&mut self) -> CaptureW<CrSpec> {
        CaptureW::new(self, 0)
    }
    #[doc = "Bit 1 - Capture mode"]
    #[inline(always)]
    #[must_use]
    pub fn cm(&mut self) -> CmW<CrSpec> {
        CmW::new(self, 1)
    }
    #[doc = "Bit 2 - Crop feature"]
    #[inline(always)]
    #[must_use]
    pub fn crop(&mut self) -> CropW<CrSpec> {
        CropW::new(self, 2)
    }
    #[doc = "Bit 3 - JPEG format"]
    #[inline(always)]
    #[must_use]
    pub fn jpeg(&mut self) -> JpegW<CrSpec> {
        JpegW::new(self, 3)
    }
    #[doc = "Bit 4 - Embedded synchronization select"]
    #[inline(always)]
    #[must_use]
    pub fn ess(&mut self) -> EssW<CrSpec> {
        EssW::new(self, 4)
    }
    #[doc = "Bit 5 - Pixel clock polarity"]
    #[inline(always)]
    #[must_use]
    pub fn pckpol(&mut self) -> PckpolW<CrSpec> {
        PckpolW::new(self, 5)
    }
    #[doc = "Bit 6 - Horizontal synchronization polarity"]
    #[inline(always)]
    #[must_use]
    pub fn hspol(&mut self) -> HspolW<CrSpec> {
        HspolW::new(self, 6)
    }
    #[doc = "Bit 7 - Vertical synchronization polarity"]
    #[inline(always)]
    #[must_use]
    pub fn vspol(&mut self) -> VspolW<CrSpec> {
        VspolW::new(self, 7)
    }
    #[doc = "Bits 8:9 - Frame capture rate control"]
    #[inline(always)]
    #[must_use]
    pub fn fcrc(&mut self) -> FcrcW<CrSpec> {
        FcrcW::new(self, 8)
    }
    #[doc = "Bits 10:11 - Extended data mode"]
    #[inline(always)]
    #[must_use]
    pub fn edm(&mut self) -> EdmW<CrSpec> {
        EdmW::new(self, 10)
    }
    #[doc = "Bit 14 - DCMI enable"]
    #[inline(always)]
    #[must_use]
    pub fn enable(&mut self) -> EnableW<CrSpec> {
        EnableW::new(self, 14)
    }
}
#[doc = "control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0;
}
