// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1CKCR` reader"]
pub type R = crate::R<L1ckcrSpec>;
#[doc = "Register `L1CKCR` writer"]
pub type W = crate::W<L1ckcrSpec>;
#[doc = "Field `CKBLUE` reader - Color Key Blue value"]
pub type CkblueR = crate::FieldReader;
#[doc = "Field `CKBLUE` writer - Color Key Blue value"]
pub type CkblueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `CKGREEN` reader - Color Key Green value"]
pub type CkgreenR = crate::FieldReader;
#[doc = "Field `CKGREEN` writer - Color Key Green value"]
pub type CkgreenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `CKRED` reader - Color Key Red value"]
pub type CkredR = crate::FieldReader;
#[doc = "Field `CKRED` writer - Color Key Red value"]
pub type CkredW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Color Key Blue value"]
    #[inline(always)]
    pub fn ckblue(&self) -> CkblueR {
        CkblueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Color Key Green value"]
    #[inline(always)]
    pub fn ckgreen(&self) -> CkgreenR {
        CkgreenR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Color Key Red value"]
    #[inline(always)]
    pub fn ckred(&self) -> CkredR {
        CkredR::new(((self.bits >> 16) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Color Key Blue value"]
    #[inline(always)]
    #[must_use]
    pub fn ckblue(&mut self) -> CkblueW<L1ckcrSpec> {
        CkblueW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Color Key Green value"]
    #[inline(always)]
    #[must_use]
    pub fn ckgreen(&mut self) -> CkgreenW<L1ckcrSpec> {
        CkgreenW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Color Key Red value"]
    #[inline(always)]
    #[must_use]
    pub fn ckred(&mut self) -> CkredW<L1ckcrSpec> {
        CkredW::new(self, 16)
    }
}
#[doc = "Layerx Color Keying Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1ckcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1ckcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1ckcrSpec;
impl crate::RegisterSpec for L1ckcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`l1ckcr::R`](R) reader structure"]
impl crate::Readable for L1ckcrSpec {}
#[doc = "`write(|w| ..)` method takes [`l1ckcr::W`](W) writer structure"]
impl crate::Writable for L1ckcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1CKCR to value 0"]
impl crate::Resettable for L1ckcrSpec {
    const RESET_VALUE: u32 = 0;
}
