// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RF0R` reader"]
pub type R = crate::R<Rf0rSpec>;
#[doc = "Register `RF0R` writer"]
pub type W = crate::W<Rf0rSpec>;
#[doc = "Field `FMP0` reader - FMP0"]
pub type Fmp0R = crate::FieldReader;
#[doc = "Field `FMP0` writer - FMP0"]
pub type Fmp0W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FULL0` reader - FULL0"]
pub type Full0R = crate::BitReader;
#[doc = "Field `FULL0` writer - FULL0"]
pub type Full0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FOVR0` reader - FOVR0"]
pub type Fovr0R = crate::BitReader;
#[doc = "Field `FOVR0` writer - FOVR0"]
pub type Fovr0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFOM0` reader - RFOM0"]
pub type Rfom0R = crate::BitReader;
#[doc = "Field `RFOM0` writer - RFOM0"]
pub type Rfom0W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - FMP0"]
    #[inline(always)]
    pub fn fmp0(&self) -> Fmp0R {
        Fmp0R::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 3 - FULL0"]
    #[inline(always)]
    pub fn full0(&self) -> Full0R {
        Full0R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - FOVR0"]
    #[inline(always)]
    pub fn fovr0(&self) -> Fovr0R {
        Fovr0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - RFOM0"]
    #[inline(always)]
    pub fn rfom0(&self) -> Rfom0R {
        Rfom0R::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - FMP0"]
    #[inline(always)]
    #[must_use]
    pub fn fmp0(&mut self) -> Fmp0W<Rf0rSpec> {
        Fmp0W::new(self, 0)
    }
    #[doc = "Bit 3 - FULL0"]
    #[inline(always)]
    #[must_use]
    pub fn full0(&mut self) -> Full0W<Rf0rSpec> {
        Full0W::new(self, 3)
    }
    #[doc = "Bit 4 - FOVR0"]
    #[inline(always)]
    #[must_use]
    pub fn fovr0(&mut self) -> Fovr0W<Rf0rSpec> {
        Fovr0W::new(self, 4)
    }
    #[doc = "Bit 5 - RFOM0"]
    #[inline(always)]
    #[must_use]
    pub fn rfom0(&mut self) -> Rfom0W<Rf0rSpec> {
        Rfom0W::new(self, 5)
    }
}
#[doc = "receive FIFO 0 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rf0r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rf0r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Rf0rSpec;
impl crate::RegisterSpec for Rf0rSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`rf0r::R`](R) reader structure"]
impl crate::Readable for Rf0rSpec {}
#[doc = "`write(|w| ..)` method takes [`rf0r::W`](W) writer structure"]
impl crate::Writable for Rf0rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RF0R to value 0"]
impl crate::Resettable for Rf0rSpec {
    const RESET_VALUE: u32 = 0;
}
