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
#[doc = "Register `OAR1` reader"]
pub type R = crate::R<Oar1Spec>;
#[doc = "Register `OAR1` writer"]
pub type W = crate::W<Oar1Spec>;
#[doc = "Field `OA1` reader - Interface address"]
pub type Oa1R = crate::FieldReader<u16>;
#[doc = "Field `OA1` writer - Interface address"]
pub type Oa1W<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `OA1MODE` reader - Own Address 1 10-bit mode"]
pub type Oa1modeR = crate::BitReader;
#[doc = "Field `OA1MODE` writer - Own Address 1 10-bit mode"]
pub type Oa1modeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OA1EN` reader - Own Address 1 enable"]
pub type Oa1enR = crate::BitReader;
#[doc = "Field `OA1EN` writer - Own Address 1 enable"]
pub type Oa1enW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:9 - Interface address"]
    #[inline(always)]
    pub fn oa1(&self) -> Oa1R {
        Oa1R::new((self.bits & 0x03ff) as u16)
    }
    #[doc = "Bit 10 - Own Address 1 10-bit mode"]
    #[inline(always)]
    pub fn oa1mode(&self) -> Oa1modeR {
        Oa1modeR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 15 - Own Address 1 enable"]
    #[inline(always)]
    pub fn oa1en(&self) -> Oa1enR {
        Oa1enR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:9 - Interface address"]
    #[inline(always)]
    #[must_use]
    pub fn oa1(&mut self) -> Oa1W<Oar1Spec> {
        Oa1W::new(self, 0)
    }
    #[doc = "Bit 10 - Own Address 1 10-bit mode"]
    #[inline(always)]
    #[must_use]
    pub fn oa1mode(&mut self) -> Oa1modeW<Oar1Spec> {
        Oa1modeW::new(self, 10)
    }
    #[doc = "Bit 15 - Own Address 1 enable"]
    #[inline(always)]
    #[must_use]
    pub fn oa1en(&mut self) -> Oa1enW<Oar1Spec> {
        Oa1enW::new(self, 15)
    }
}
#[doc = "Own address register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`oar1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`oar1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Oar1Spec;
impl crate::RegisterSpec for Oar1Spec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`oar1::R`](R) reader structure"]
impl crate::Readable for Oar1Spec {}
#[doc = "`write(|w| ..)` method takes [`oar1::W`](W) writer structure"]
impl crate::Writable for Oar1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OAR1 to value 0"]
impl crate::Resettable for Oar1Spec {
    const RESET_VALUE: u32 = 0;
}
