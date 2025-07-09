// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1DCCR` reader"]
pub type R = crate::R<L1dccrSpec>;
#[doc = "Register `L1DCCR` writer"]
pub type W = crate::W<L1dccrSpec>;
#[doc = "Field `DCBLUE` reader - Default Color Blue"]
pub type DcblueR = crate::FieldReader;
#[doc = "Field `DCBLUE` writer - Default Color Blue"]
pub type DcblueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DCGREEN` reader - Default Color Green"]
pub type DcgreenR = crate::FieldReader;
#[doc = "Field `DCGREEN` writer - Default Color Green"]
pub type DcgreenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DCRED` reader - Default Color Red"]
pub type DcredR = crate::FieldReader;
#[doc = "Field `DCRED` writer - Default Color Red"]
pub type DcredW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DCALPHA` reader - Default Color Alpha"]
pub type DcalphaR = crate::FieldReader;
#[doc = "Field `DCALPHA` writer - Default Color Alpha"]
pub type DcalphaW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Default Color Blue"]
    #[inline(always)]
    pub fn dcblue(&self) -> DcblueR {
        DcblueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Default Color Green"]
    #[inline(always)]
    pub fn dcgreen(&self) -> DcgreenR {
        DcgreenR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Default Color Red"]
    #[inline(always)]
    pub fn dcred(&self) -> DcredR {
        DcredR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - Default Color Alpha"]
    #[inline(always)]
    pub fn dcalpha(&self) -> DcalphaR {
        DcalphaR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Default Color Blue"]
    #[inline(always)]
    #[must_use]
    pub fn dcblue(&mut self) -> DcblueW<L1dccrSpec> {
        DcblueW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Default Color Green"]
    #[inline(always)]
    #[must_use]
    pub fn dcgreen(&mut self) -> DcgreenW<L1dccrSpec> {
        DcgreenW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Default Color Red"]
    #[inline(always)]
    #[must_use]
    pub fn dcred(&mut self) -> DcredW<L1dccrSpec> {
        DcredW::new(self, 16)
    }
    #[doc = "Bits 24:31 - Default Color Alpha"]
    #[inline(always)]
    #[must_use]
    pub fn dcalpha(&mut self) -> DcalphaW<L1dccrSpec> {
        DcalphaW::new(self, 24)
    }
}
#[doc = "Layerx Default Color Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1dccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1dccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1dccrSpec;
impl crate::RegisterSpec for L1dccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 156u64;
}
#[doc = "`read()` method returns [`l1dccr::R`](R) reader structure"]
impl crate::Readable for L1dccrSpec {}
#[doc = "`write(|w| ..)` method takes [`l1dccr::W`](W) writer structure"]
impl crate::Writable for L1dccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1DCCR to value 0"]
impl crate::Resettable for L1dccrSpec {
    const RESET_VALUE: u32 = 0;
}
