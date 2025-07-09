// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `EXTICR4` reader"]
pub type R = crate::R<Exticr4Spec>;
#[doc = "Register `EXTICR4` writer"]
pub type W = crate::W<Exticr4Spec>;
#[doc = "Field `EXTI12` reader - EXTI x configuration (x = 12 to 15)"]
pub type Exti12R = crate::FieldReader;
#[doc = "Field `EXTI12` writer - EXTI x configuration (x = 12 to 15)"]
pub type Exti12W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI13` reader - EXTI x configuration (x = 12 to 15)"]
pub type Exti13R = crate::FieldReader;
#[doc = "Field `EXTI13` writer - EXTI x configuration (x = 12 to 15)"]
pub type Exti13W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI14` reader - EXTI x configuration (x = 12 to 15)"]
pub type Exti14R = crate::FieldReader;
#[doc = "Field `EXTI14` writer - EXTI x configuration (x = 12 to 15)"]
pub type Exti14W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI15` reader - EXTI x configuration (x = 12 to 15)"]
pub type Exti15R = crate::FieldReader;
#[doc = "Field `EXTI15` writer - EXTI x configuration (x = 12 to 15)"]
pub type Exti15W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    pub fn exti12(&self) -> Exti12R {
        Exti12R::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    pub fn exti13(&self) -> Exti13R {
        Exti13R::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    pub fn exti14(&self) -> Exti14R {
        Exti14R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:15 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    pub fn exti15(&self) -> Exti15R {
        Exti15R::new(((self.bits >> 12) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    #[must_use]
    pub fn exti12(&mut self) -> Exti12W<Exticr4Spec> {
        Exti12W::new(self, 0)
    }
    #[doc = "Bits 4:7 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    #[must_use]
    pub fn exti13(&mut self) -> Exti13W<Exticr4Spec> {
        Exti13W::new(self, 4)
    }
    #[doc = "Bits 8:11 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    #[must_use]
    pub fn exti14(&mut self) -> Exti14W<Exticr4Spec> {
        Exti14W::new(self, 8)
    }
    #[doc = "Bits 12:15 - EXTI x configuration (x = 12 to 15)"]
    #[inline(always)]
    #[must_use]
    pub fn exti15(&mut self) -> Exti15W<Exticr4Spec> {
        Exti15W::new(self, 12)
    }
}
#[doc = "external interrupt configuration register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`exticr4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`exticr4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Exticr4Spec;
impl crate::RegisterSpec for Exticr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`exticr4::R`](R) reader structure"]
impl crate::Readable for Exticr4Spec {}
#[doc = "`write(|w| ..)` method takes [`exticr4::W`](W) writer structure"]
impl crate::Writable for Exticr4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets EXTICR4 to value 0"]
impl crate::Resettable for Exticr4Spec {
    const RESET_VALUE: u32 = 0;
}
