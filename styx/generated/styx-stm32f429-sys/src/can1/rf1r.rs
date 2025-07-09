// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RF1R` reader"]
pub type R = crate::R<Rf1rSpec>;
#[doc = "Register `RF1R` writer"]
pub type W = crate::W<Rf1rSpec>;
#[doc = "Field `FMP1` reader - FMP1"]
pub type Fmp1R = crate::FieldReader;
#[doc = "Field `FMP1` writer - FMP1"]
pub type Fmp1W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FULL1` reader - FULL1"]
pub type Full1R = crate::BitReader;
#[doc = "Field `FULL1` writer - FULL1"]
pub type Full1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FOVR1` reader - FOVR1"]
pub type Fovr1R = crate::BitReader;
#[doc = "Field `FOVR1` writer - FOVR1"]
pub type Fovr1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFOM1` reader - RFOM1"]
pub type Rfom1R = crate::BitReader;
#[doc = "Field `RFOM1` writer - RFOM1"]
pub type Rfom1W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - FMP1"]
    #[inline(always)]
    pub fn fmp1(&self) -> Fmp1R {
        Fmp1R::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 3 - FULL1"]
    #[inline(always)]
    pub fn full1(&self) -> Full1R {
        Full1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - FOVR1"]
    #[inline(always)]
    pub fn fovr1(&self) -> Fovr1R {
        Fovr1R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - RFOM1"]
    #[inline(always)]
    pub fn rfom1(&self) -> Rfom1R {
        Rfom1R::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - FMP1"]
    #[inline(always)]
    #[must_use]
    pub fn fmp1(&mut self) -> Fmp1W<Rf1rSpec> {
        Fmp1W::new(self, 0)
    }
    #[doc = "Bit 3 - FULL1"]
    #[inline(always)]
    #[must_use]
    pub fn full1(&mut self) -> Full1W<Rf1rSpec> {
        Full1W::new(self, 3)
    }
    #[doc = "Bit 4 - FOVR1"]
    #[inline(always)]
    #[must_use]
    pub fn fovr1(&mut self) -> Fovr1W<Rf1rSpec> {
        Fovr1W::new(self, 4)
    }
    #[doc = "Bit 5 - RFOM1"]
    #[inline(always)]
    #[must_use]
    pub fn rfom1(&mut self) -> Rfom1W<Rf1rSpec> {
        Rfom1W::new(self, 5)
    }
}
#[doc = "receive FIFO 1 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rf1r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rf1r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Rf1rSpec;
impl crate::RegisterSpec for Rf1rSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`rf1r::R`](R) reader structure"]
impl crate::Readable for Rf1rSpec {}
#[doc = "`write(|w| ..)` method takes [`rf1r::W`](W) writer structure"]
impl crate::Writable for Rf1rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RF1R to value 0"]
impl crate::Resettable for Rf1rSpec {
    const RESET_VALUE: u32 = 0;
}
