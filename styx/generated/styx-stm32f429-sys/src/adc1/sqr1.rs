// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SQR1` reader"]
pub type R = crate::R<Sqr1Spec>;
#[doc = "Register `SQR1` writer"]
pub type W = crate::W<Sqr1Spec>;
#[doc = "Field `SQ13` reader - 13th conversion in regular sequence"]
pub type Sq13R = crate::FieldReader;
#[doc = "Field `SQ13` writer - 13th conversion in regular sequence"]
pub type Sq13W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ14` reader - 14th conversion in regular sequence"]
pub type Sq14R = crate::FieldReader;
#[doc = "Field `SQ14` writer - 14th conversion in regular sequence"]
pub type Sq14W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ15` reader - 15th conversion in regular sequence"]
pub type Sq15R = crate::FieldReader;
#[doc = "Field `SQ15` writer - 15th conversion in regular sequence"]
pub type Sq15W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ16` reader - 16th conversion in regular sequence"]
pub type Sq16R = crate::FieldReader;
#[doc = "Field `SQ16` writer - 16th conversion in regular sequence"]
pub type Sq16W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `L` reader - Regular channel sequence length"]
pub type LR = crate::FieldReader;
#[doc = "Field `L` writer - Regular channel sequence length"]
pub type LW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:4 - 13th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq13(&self) -> Sq13R {
        Sq13R::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 5:9 - 14th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq14(&self) -> Sq14R {
        Sq14R::new(((self.bits >> 5) & 0x1f) as u8)
    }
    #[doc = "Bits 10:14 - 15th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq15(&self) -> Sq15R {
        Sq15R::new(((self.bits >> 10) & 0x1f) as u8)
    }
    #[doc = "Bits 15:19 - 16th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq16(&self) -> Sq16R {
        Sq16R::new(((self.bits >> 15) & 0x1f) as u8)
    }
    #[doc = "Bits 20:23 - Regular channel sequence length"]
    #[inline(always)]
    pub fn l(&self) -> LR {
        LR::new(((self.bits >> 20) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - 13th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq13(&mut self) -> Sq13W<Sqr1Spec> {
        Sq13W::new(self, 0)
    }
    #[doc = "Bits 5:9 - 14th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq14(&mut self) -> Sq14W<Sqr1Spec> {
        Sq14W::new(self, 5)
    }
    #[doc = "Bits 10:14 - 15th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq15(&mut self) -> Sq15W<Sqr1Spec> {
        Sq15W::new(self, 10)
    }
    #[doc = "Bits 15:19 - 16th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq16(&mut self) -> Sq16W<Sqr1Spec> {
        Sq16W::new(self, 15)
    }
    #[doc = "Bits 20:23 - Regular channel sequence length"]
    #[inline(always)]
    #[must_use]
    pub fn l(&mut self) -> LW<Sqr1Spec> {
        LW::new(self, 20)
    }
}
#[doc = "regular sequence register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sqr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sqr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sqr1Spec;
impl crate::RegisterSpec for Sqr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`sqr1::R`](R) reader structure"]
impl crate::Readable for Sqr1Spec {}
#[doc = "`write(|w| ..)` method takes [`sqr1::W`](W) writer structure"]
impl crate::Writable for Sqr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SQR1 to value 0"]
impl crate::Resettable for Sqr1Spec {
    const RESET_VALUE: u32 = 0;
}
