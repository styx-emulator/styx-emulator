// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `DRDY` reader - Data ready"]
pub type DrdyR = crate::BitReader;
#[doc = "Field `DRDY` writer - Data ready"]
pub type DrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CECS` reader - Clock error current status"]
pub type CecsR = crate::BitReader;
#[doc = "Field `CECS` writer - Clock error current status"]
pub type CecsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SECS` reader - Seed error current status"]
pub type SecsR = crate::BitReader;
#[doc = "Field `SECS` writer - Seed error current status"]
pub type SecsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CEIS` reader - Clock error interrupt status"]
pub type CeisR = crate::BitReader;
#[doc = "Field `CEIS` writer - Clock error interrupt status"]
pub type CeisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SEIS` reader - Seed error interrupt status"]
pub type SeisR = crate::BitReader;
#[doc = "Field `SEIS` writer - Seed error interrupt status"]
pub type SeisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Data ready"]
    #[inline(always)]
    pub fn drdy(&self) -> DrdyR {
        DrdyR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Clock error current status"]
    #[inline(always)]
    pub fn cecs(&self) -> CecsR {
        CecsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Seed error current status"]
    #[inline(always)]
    pub fn secs(&self) -> SecsR {
        SecsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 5 - Clock error interrupt status"]
    #[inline(always)]
    pub fn ceis(&self) -> CeisR {
        CeisR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Seed error interrupt status"]
    #[inline(always)]
    pub fn seis(&self) -> SeisR {
        SeisR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Data ready"]
    #[inline(always)]
    #[must_use]
    pub fn drdy(&mut self) -> DrdyW<SrSpec> {
        DrdyW::new(self, 0)
    }
    #[doc = "Bit 1 - Clock error current status"]
    #[inline(always)]
    #[must_use]
    pub fn cecs(&mut self) -> CecsW<SrSpec> {
        CecsW::new(self, 1)
    }
    #[doc = "Bit 2 - Seed error current status"]
    #[inline(always)]
    #[must_use]
    pub fn secs(&mut self) -> SecsW<SrSpec> {
        SecsW::new(self, 2)
    }
    #[doc = "Bit 5 - Clock error interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn ceis(&mut self) -> CeisW<SrSpec> {
        CeisW::new(self, 5)
    }
    #[doc = "Bit 6 - Seed error interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn seis(&mut self) -> SeisW<SrSpec> {
        SeisW::new(self, 6)
    }
}
#[doc = "status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`write(|w| ..)` method takes [`sr::W`](W) writer structure"]
impl crate::Writable for SrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
