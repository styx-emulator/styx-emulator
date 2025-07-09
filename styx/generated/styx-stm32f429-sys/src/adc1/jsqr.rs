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
#[doc = "Register `JSQR` reader"]
pub type R = crate::R<JsqrSpec>;
#[doc = "Register `JSQR` writer"]
pub type W = crate::W<JsqrSpec>;
#[doc = "Field `JSQ1` reader - 1st conversion in injected sequence"]
pub type Jsq1R = crate::FieldReader;
#[doc = "Field `JSQ1` writer - 1st conversion in injected sequence"]
pub type Jsq1W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `JSQ2` reader - 2nd conversion in injected sequence"]
pub type Jsq2R = crate::FieldReader;
#[doc = "Field `JSQ2` writer - 2nd conversion in injected sequence"]
pub type Jsq2W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `JSQ3` reader - 3rd conversion in injected sequence"]
pub type Jsq3R = crate::FieldReader;
#[doc = "Field `JSQ3` writer - 3rd conversion in injected sequence"]
pub type Jsq3W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `JSQ4` reader - 4th conversion in injected sequence"]
pub type Jsq4R = crate::FieldReader;
#[doc = "Field `JSQ4` writer - 4th conversion in injected sequence"]
pub type Jsq4W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `JL` reader - Injected sequence length"]
pub type JlR = crate::FieldReader;
#[doc = "Field `JL` writer - Injected sequence length"]
pub type JlW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:4 - 1st conversion in injected sequence"]
    #[inline(always)]
    pub fn jsq1(&self) -> Jsq1R {
        Jsq1R::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 5:9 - 2nd conversion in injected sequence"]
    #[inline(always)]
    pub fn jsq2(&self) -> Jsq2R {
        Jsq2R::new(((self.bits >> 5) & 0x1f) as u8)
    }
    #[doc = "Bits 10:14 - 3rd conversion in injected sequence"]
    #[inline(always)]
    pub fn jsq3(&self) -> Jsq3R {
        Jsq3R::new(((self.bits >> 10) & 0x1f) as u8)
    }
    #[doc = "Bits 15:19 - 4th conversion in injected sequence"]
    #[inline(always)]
    pub fn jsq4(&self) -> Jsq4R {
        Jsq4R::new(((self.bits >> 15) & 0x1f) as u8)
    }
    #[doc = "Bits 20:21 - Injected sequence length"]
    #[inline(always)]
    pub fn jl(&self) -> JlR {
        JlR::new(((self.bits >> 20) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - 1st conversion in injected sequence"]
    #[inline(always)]
    #[must_use]
    pub fn jsq1(&mut self) -> Jsq1W<JsqrSpec> {
        Jsq1W::new(self, 0)
    }
    #[doc = "Bits 5:9 - 2nd conversion in injected sequence"]
    #[inline(always)]
    #[must_use]
    pub fn jsq2(&mut self) -> Jsq2W<JsqrSpec> {
        Jsq2W::new(self, 5)
    }
    #[doc = "Bits 10:14 - 3rd conversion in injected sequence"]
    #[inline(always)]
    #[must_use]
    pub fn jsq3(&mut self) -> Jsq3W<JsqrSpec> {
        Jsq3W::new(self, 10)
    }
    #[doc = "Bits 15:19 - 4th conversion in injected sequence"]
    #[inline(always)]
    #[must_use]
    pub fn jsq4(&mut self) -> Jsq4W<JsqrSpec> {
        Jsq4W::new(self, 15)
    }
    #[doc = "Bits 20:21 - Injected sequence length"]
    #[inline(always)]
    #[must_use]
    pub fn jl(&mut self) -> JlW<JsqrSpec> {
        JlW::new(self, 20)
    }
}
#[doc = "injected sequence register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jsqr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jsqr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct JsqrSpec;
impl crate::RegisterSpec for JsqrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`jsqr::R`](R) reader structure"]
impl crate::Readable for JsqrSpec {}
#[doc = "`write(|w| ..)` method takes [`jsqr::W`](W) writer structure"]
impl crate::Writable for JsqrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets JSQR to value 0"]
impl crate::Resettable for JsqrSpec {
    const RESET_VALUE: u32 = 0;
}
