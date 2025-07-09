// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR1` reader"]
pub type R = crate::R<Cr1Spec>;
#[doc = "Register `CR1` writer"]
pub type W = crate::W<Cr1Spec>;
#[doc = "Field `CEN` reader - Counter enable"]
pub type CenR = crate::BitReader;
#[doc = "Field `CEN` writer - Counter enable"]
pub type CenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UDIS` reader - Update disable"]
pub type UdisR = crate::BitReader;
#[doc = "Field `UDIS` writer - Update disable"]
pub type UdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `URS` reader - Update request source"]
pub type UrsR = crate::BitReader;
#[doc = "Field `URS` writer - Update request source"]
pub type UrsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OPM` reader - One-pulse mode"]
pub type OpmR = crate::BitReader;
#[doc = "Field `OPM` writer - One-pulse mode"]
pub type OpmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DIR` reader - Direction"]
pub type DirR = crate::BitReader;
#[doc = "Field `DIR` writer - Direction"]
pub type DirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMS` reader - Center-aligned mode selection"]
pub type CmsR = crate::FieldReader;
#[doc = "Field `CMS` writer - Center-aligned mode selection"]
pub type CmsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ARPE` reader - Auto-reload preload enable"]
pub type ArpeR = crate::BitReader;
#[doc = "Field `ARPE` writer - Auto-reload preload enable"]
pub type ArpeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CKD` reader - Clock division"]
pub type CkdR = crate::FieldReader;
#[doc = "Field `CKD` writer - Clock division"]
pub type CkdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Counter enable"]
    #[inline(always)]
    pub fn cen(&self) -> CenR {
        CenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Update disable"]
    #[inline(always)]
    pub fn udis(&self) -> UdisR {
        UdisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Update request source"]
    #[inline(always)]
    pub fn urs(&self) -> UrsR {
        UrsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - One-pulse mode"]
    #[inline(always)]
    pub fn opm(&self) -> OpmR {
        OpmR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Direction"]
    #[inline(always)]
    pub fn dir(&self) -> DirR {
        DirR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:6 - Center-aligned mode selection"]
    #[inline(always)]
    pub fn cms(&self) -> CmsR {
        CmsR::new(((self.bits >> 5) & 3) as u8)
    }
    #[doc = "Bit 7 - Auto-reload preload enable"]
    #[inline(always)]
    pub fn arpe(&self) -> ArpeR {
        ArpeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:9 - Clock division"]
    #[inline(always)]
    pub fn ckd(&self) -> CkdR {
        CkdR::new(((self.bits >> 8) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Counter enable"]
    #[inline(always)]
    #[must_use]
    pub fn cen(&mut self) -> CenW<Cr1Spec> {
        CenW::new(self, 0)
    }
    #[doc = "Bit 1 - Update disable"]
    #[inline(always)]
    #[must_use]
    pub fn udis(&mut self) -> UdisW<Cr1Spec> {
        UdisW::new(self, 1)
    }
    #[doc = "Bit 2 - Update request source"]
    #[inline(always)]
    #[must_use]
    pub fn urs(&mut self) -> UrsW<Cr1Spec> {
        UrsW::new(self, 2)
    }
    #[doc = "Bit 3 - One-pulse mode"]
    #[inline(always)]
    #[must_use]
    pub fn opm(&mut self) -> OpmW<Cr1Spec> {
        OpmW::new(self, 3)
    }
    #[doc = "Bit 4 - Direction"]
    #[inline(always)]
    #[must_use]
    pub fn dir(&mut self) -> DirW<Cr1Spec> {
        DirW::new(self, 4)
    }
    #[doc = "Bits 5:6 - Center-aligned mode selection"]
    #[inline(always)]
    #[must_use]
    pub fn cms(&mut self) -> CmsW<Cr1Spec> {
        CmsW::new(self, 5)
    }
    #[doc = "Bit 7 - Auto-reload preload enable"]
    #[inline(always)]
    #[must_use]
    pub fn arpe(&mut self) -> ArpeW<Cr1Spec> {
        ArpeW::new(self, 7)
    }
    #[doc = "Bits 8:9 - Clock division"]
    #[inline(always)]
    #[must_use]
    pub fn ckd(&mut self) -> CkdW<Cr1Spec> {
        CkdW::new(self, 8)
    }
}
#[doc = "control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr1Spec;
impl crate::RegisterSpec for Cr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr1::R`](R) reader structure"]
impl crate::Readable for Cr1Spec {}
#[doc = "`write(|w| ..)` method takes [`cr1::W`](W) writer structure"]
impl crate::Writable for Cr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR1 to value 0"]
impl crate::Resettable for Cr1Spec {
    const RESET_VALUE: u32 = 0;
}
