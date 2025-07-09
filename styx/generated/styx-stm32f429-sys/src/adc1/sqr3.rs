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
#[doc = "Register `SQR3` reader"]
pub type R = crate::R<Sqr3Spec>;
#[doc = "Register `SQR3` writer"]
pub type W = crate::W<Sqr3Spec>;
#[doc = "Field `SQ1` reader - 1st conversion in regular sequence"]
pub type Sq1R = crate::FieldReader;
#[doc = "Field `SQ1` writer - 1st conversion in regular sequence"]
pub type Sq1W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ2` reader - 2nd conversion in regular sequence"]
pub type Sq2R = crate::FieldReader;
#[doc = "Field `SQ2` writer - 2nd conversion in regular sequence"]
pub type Sq2W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ3` reader - 3rd conversion in regular sequence"]
pub type Sq3R = crate::FieldReader;
#[doc = "Field `SQ3` writer - 3rd conversion in regular sequence"]
pub type Sq3W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ4` reader - 4th conversion in regular sequence"]
pub type Sq4R = crate::FieldReader;
#[doc = "Field `SQ4` writer - 4th conversion in regular sequence"]
pub type Sq4W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ5` reader - 5th conversion in regular sequence"]
pub type Sq5R = crate::FieldReader;
#[doc = "Field `SQ5` writer - 5th conversion in regular sequence"]
pub type Sq5W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SQ6` reader - 6th conversion in regular sequence"]
pub type Sq6R = crate::FieldReader;
#[doc = "Field `SQ6` writer - 6th conversion in regular sequence"]
pub type Sq6W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - 1st conversion in regular sequence"]
    #[inline(always)]
    pub fn sq1(&self) -> Sq1R {
        Sq1R::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 5:9 - 2nd conversion in regular sequence"]
    #[inline(always)]
    pub fn sq2(&self) -> Sq2R {
        Sq2R::new(((self.bits >> 5) & 0x1f) as u8)
    }
    #[doc = "Bits 10:14 - 3rd conversion in regular sequence"]
    #[inline(always)]
    pub fn sq3(&self) -> Sq3R {
        Sq3R::new(((self.bits >> 10) & 0x1f) as u8)
    }
    #[doc = "Bits 15:19 - 4th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq4(&self) -> Sq4R {
        Sq4R::new(((self.bits >> 15) & 0x1f) as u8)
    }
    #[doc = "Bits 20:24 - 5th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq5(&self) -> Sq5R {
        Sq5R::new(((self.bits >> 20) & 0x1f) as u8)
    }
    #[doc = "Bits 25:29 - 6th conversion in regular sequence"]
    #[inline(always)]
    pub fn sq6(&self) -> Sq6R {
        Sq6R::new(((self.bits >> 25) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - 1st conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq1(&mut self) -> Sq1W<Sqr3Spec> {
        Sq1W::new(self, 0)
    }
    #[doc = "Bits 5:9 - 2nd conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq2(&mut self) -> Sq2W<Sqr3Spec> {
        Sq2W::new(self, 5)
    }
    #[doc = "Bits 10:14 - 3rd conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq3(&mut self) -> Sq3W<Sqr3Spec> {
        Sq3W::new(self, 10)
    }
    #[doc = "Bits 15:19 - 4th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq4(&mut self) -> Sq4W<Sqr3Spec> {
        Sq4W::new(self, 15)
    }
    #[doc = "Bits 20:24 - 5th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq5(&mut self) -> Sq5W<Sqr3Spec> {
        Sq5W::new(self, 20)
    }
    #[doc = "Bits 25:29 - 6th conversion in regular sequence"]
    #[inline(always)]
    #[must_use]
    pub fn sq6(&mut self) -> Sq6W<Sqr3Spec> {
        Sq6W::new(self, 25)
    }
}
#[doc = "regular sequence register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sqr3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sqr3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sqr3Spec;
impl crate::RegisterSpec for Sqr3Spec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`sqr3::R`](R) reader structure"]
impl crate::Readable for Sqr3Spec {}
#[doc = "`write(|w| ..)` method takes [`sqr3::W`](W) writer structure"]
impl crate::Writable for Sqr3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SQR3 to value 0"]
impl crate::Resettable for Sqr3Spec {
    const RESET_VALUE: u32 = 0;
}
