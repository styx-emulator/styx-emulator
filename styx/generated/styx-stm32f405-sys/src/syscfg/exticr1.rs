// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `EXTICR1` reader"]
pub type R = crate::R<Exticr1Spec>;
#[doc = "Register `EXTICR1` writer"]
pub type W = crate::W<Exticr1Spec>;
#[doc = "Field `EXTI0` reader - EXTI x configuration (x = 0 to 3)"]
pub type Exti0R = crate::FieldReader;
#[doc = "Field `EXTI0` writer - EXTI x configuration (x = 0 to 3)"]
pub type Exti0W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI1` reader - EXTI x configuration (x = 0 to 3)"]
pub type Exti1R = crate::FieldReader;
#[doc = "Field `EXTI1` writer - EXTI x configuration (x = 0 to 3)"]
pub type Exti1W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI2` reader - EXTI x configuration (x = 0 to 3)"]
pub type Exti2R = crate::FieldReader;
#[doc = "Field `EXTI2` writer - EXTI x configuration (x = 0 to 3)"]
pub type Exti2W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI3` reader - EXTI x configuration (x = 0 to 3)"]
pub type Exti3R = crate::FieldReader;
#[doc = "Field `EXTI3` writer - EXTI x configuration (x = 0 to 3)"]
pub type Exti3W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    pub fn exti0(&self) -> Exti0R {
        Exti0R::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    pub fn exti1(&self) -> Exti1R {
        Exti1R::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    pub fn exti2(&self) -> Exti2R {
        Exti2R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:15 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    pub fn exti3(&self) -> Exti3R {
        Exti3R::new(((self.bits >> 12) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    #[must_use]
    pub fn exti0(&mut self) -> Exti0W<Exticr1Spec> {
        Exti0W::new(self, 0)
    }
    #[doc = "Bits 4:7 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    #[must_use]
    pub fn exti1(&mut self) -> Exti1W<Exticr1Spec> {
        Exti1W::new(self, 4)
    }
    #[doc = "Bits 8:11 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    #[must_use]
    pub fn exti2(&mut self) -> Exti2W<Exticr1Spec> {
        Exti2W::new(self, 8)
    }
    #[doc = "Bits 12:15 - EXTI x configuration (x = 0 to 3)"]
    #[inline(always)]
    #[must_use]
    pub fn exti3(&mut self) -> Exti3W<Exticr1Spec> {
        Exti3W::new(self, 12)
    }
}
#[doc = "external interrupt configuration register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`exticr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`exticr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Exticr1Spec;
impl crate::RegisterSpec for Exticr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`exticr1::R`](R) reader structure"]
impl crate::Readable for Exticr1Spec {}
#[doc = "`write(|w| ..)` method takes [`exticr1::W`](W) writer structure"]
impl crate::Writable for Exticr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets EXTICR1 to value 0"]
impl crate::Resettable for Exticr1Spec {
    const RESET_VALUE: u32 = 0;
}
