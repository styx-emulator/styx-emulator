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
#[doc = "Register `EXTICR3` reader"]
pub type R = crate::R<Exticr3Spec>;
#[doc = "Register `EXTICR3` writer"]
pub type W = crate::W<Exticr3Spec>;
#[doc = "Field `EXTI8` reader - EXTI x configuration (x = 8 to 11)"]
pub type Exti8R = crate::FieldReader;
#[doc = "Field `EXTI8` writer - EXTI x configuration (x = 8 to 11)"]
pub type Exti8W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI9` reader - EXTI x configuration (x = 8 to 11)"]
pub type Exti9R = crate::FieldReader;
#[doc = "Field `EXTI9` writer - EXTI x configuration (x = 8 to 11)"]
pub type Exti9W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI10` reader - EXTI10"]
pub type Exti10R = crate::FieldReader;
#[doc = "Field `EXTI10` writer - EXTI10"]
pub type Exti10W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTI11` reader - EXTI x configuration (x = 8 to 11)"]
pub type Exti11R = crate::FieldReader;
#[doc = "Field `EXTI11` writer - EXTI x configuration (x = 8 to 11)"]
pub type Exti11W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - EXTI x configuration (x = 8 to 11)"]
    #[inline(always)]
    pub fn exti8(&self) -> Exti8R {
        Exti8R::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - EXTI x configuration (x = 8 to 11)"]
    #[inline(always)]
    pub fn exti9(&self) -> Exti9R {
        Exti9R::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - EXTI10"]
    #[inline(always)]
    pub fn exti10(&self) -> Exti10R {
        Exti10R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:15 - EXTI x configuration (x = 8 to 11)"]
    #[inline(always)]
    pub fn exti11(&self) -> Exti11R {
        Exti11R::new(((self.bits >> 12) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - EXTI x configuration (x = 8 to 11)"]
    #[inline(always)]
    #[must_use]
    pub fn exti8(&mut self) -> Exti8W<Exticr3Spec> {
        Exti8W::new(self, 0)
    }
    #[doc = "Bits 4:7 - EXTI x configuration (x = 8 to 11)"]
    #[inline(always)]
    #[must_use]
    pub fn exti9(&mut self) -> Exti9W<Exticr3Spec> {
        Exti9W::new(self, 4)
    }
    #[doc = "Bits 8:11 - EXTI10"]
    #[inline(always)]
    #[must_use]
    pub fn exti10(&mut self) -> Exti10W<Exticr3Spec> {
        Exti10W::new(self, 8)
    }
    #[doc = "Bits 12:15 - EXTI x configuration (x = 8 to 11)"]
    #[inline(always)]
    #[must_use]
    pub fn exti11(&mut self) -> Exti11W<Exticr3Spec> {
        Exti11W::new(self, 12)
    }
}
#[doc = "external interrupt configuration register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`exticr3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`exticr3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Exticr3Spec;
impl crate::RegisterSpec for Exticr3Spec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`exticr3::R`](R) reader structure"]
impl crate::Readable for Exticr3Spec {}
#[doc = "`write(|w| ..)` method takes [`exticr3::W`](W) writer structure"]
impl crate::Writable for Exticr3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets EXTICR3 to value 0"]
impl crate::Resettable for Exticr3Spec {
    const RESET_VALUE: u32 = 0;
}
