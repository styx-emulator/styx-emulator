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
#[doc = "Register `SQR2` reader"]
pub type R = crate::R<Sqr2Spec>;
#[doc = "Register `SQR2` writer"]
pub type W = crate::W<Sqr2Spec>;
#[doc = "Field `SQ7` reader - 7th conversion in regular sequence"]
pub type Sq7R = crate::FieldReader;
#[doc = "Field `SQ7` writer - 7th conversion in regular sequence"]
pub type Sq7W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ8` reader - 8th conversion in regular sequence"]
pub type Sq8R = crate::FieldReader;
#[doc = "Field `SQ8` writer - 8th conversion in regular sequence"]
pub type Sq8W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ9` reader - 9th conversion in regular sequence"]
pub type Sq9R = crate::FieldReader;
#[doc = "Field `SQ9` writer - 9th conversion in regular sequence"]
pub type Sq9W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ10` reader - 10th conversion in regular sequence"]
pub type Sq10R = crate::FieldReader;
#[doc = "Field `SQ10` writer - 10th conversion in regular sequence"]
pub type Sq10W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ11` reader - 11th conversion in regular sequence"]
pub type Sq11R = crate::FieldReader;
#[doc = "Field `SQ11` writer - 11th conversion in regular sequence"]
pub type Sq11W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ12` reader - 12th conversion in regular sequence"]
pub type Sq12R = crate::FieldReader;
#[doc = "Field `SQ12` writer - 12th conversion in regular sequence"]
pub type Sq12W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - 7th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq7(&self) -> Sq7R {
        Sq7R::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 5:9 - 8th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq8(&self) -> Sq8R {
        Sq8R::new(((self.bits >> 5) & 0x1f) as u8)
    }
    #[doc = "Bits 10:14 - 9th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq9(&self) -> Sq9R {
        Sq9R::new(((self.bits >> 10) & 0x1f) as u8)
    }
    #[doc = "Bits 15:19 - 10th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq10(&self) -> Sq10R {
        Sq10R::new(((self.bits >> 15) & 0x1f) as u8)
    }
    #[doc = "Bits 20:24 - 11th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq11(&self) -> Sq11R {
        Sq11R::new(((self.bits >> 20) & 0x1f) as u8)
    }
    #[doc = "Bits 25:29 - 12th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq12(&self) -> Sq12R {
        Sq12R::new(((self.bits >> 25) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - 7th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq7(&mut self) -> Sq7W<Sqr2Spec> {
        Sq7W::new(self, 0)
    }
    #[doc = "Bits 5:9 - 8th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq8(&mut self) -> Sq8W<Sqr2Spec> {
        Sq8W::new(self, 5)
    }
    #[doc = "Bits 10:14 - 9th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq9(&mut self) -> Sq9W<Sqr2Spec> {
        Sq9W::new(self, 10)
    }
    #[doc = "Bits 15:19 - 10th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq10(&mut self) -> Sq10W<Sqr2Spec> {
        Sq10W::new(self, 15)
    }
    #[doc = "Bits 20:24 - 11th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq11(&mut self) -> Sq11W<Sqr2Spec> {
        Sq11W::new(self, 20)
    }
    #[doc = "Bits 25:29 - 12th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq12(&mut self) -> Sq12W<Sqr2Spec> {
        Sq12W::new(self, 25)
    }
}
#[doc = "regular sequence register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sqr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sqr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sqr2Spec;
impl crate::RegisterSpec for Sqr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`sqr2::R`](R) reader structure"]
impl crate::Readable for Sqr2Spec {}
#[doc = "`write(|w| ..)` method takes [`sqr2::W`](W) writer structure"]
impl crate::Writable for Sqr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SQR2 to value 0"]
impl crate::Resettable for Sqr2Spec {
    const RESET_VALUE: u32 = 0;
}
