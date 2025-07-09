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
#[doc = "Register `ESCR` reader"]
pub type R = crate::R<EscrSpec>;
#[doc = "Register `ESCR` writer"]
pub type W = crate::W<EscrSpec>;
#[doc = "Field `FSC` reader - Frame start delimiter code"]
pub type FscR = crate::FieldReader;
#[doc = "Field `FSC` writer - Frame start delimiter code"]
pub type FscW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `LSC` reader - Line start delimiter code"]
pub type LscR = crate::FieldReader;
#[doc = "Field `LSC` writer - Line start delimiter code"]
pub type LscW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `LEC` reader - Line end delimiter code"]
pub type LecR = crate::FieldReader;
#[doc = "Field `LEC` writer - Line end delimiter code"]
pub type LecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `FEC` reader - Frame end delimiter code"]
pub type FecR = crate::FieldReader;
#[doc = "Field `FEC` writer - Frame end delimiter code"]
pub type FecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Frame start delimiter code"]
    #[inline(always)]
    pub fn fsc(&self) -> FscR {
        FscR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Line start delimiter code"]
    #[inline(always)]
    pub fn lsc(&self) -> LscR {
        LscR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Line end delimiter code"]
    #[inline(always)]
    pub fn lec(&self) -> LecR {
        LecR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - Frame end delimiter code"]
    #[inline(always)]
    pub fn fec(&self) -> FecR {
        FecR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Frame start delimiter code"]
    #[inline(always)]
    #[must_use]
    pub fn fsc(&mut self) -> FscW<EscrSpec> {
        FscW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Line start delimiter code"]
    #[inline(always)]
    #[must_use]
    pub fn lsc(&mut self) -> LscW<EscrSpec> {
        LscW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Line end delimiter code"]
    #[inline(always)]
    #[must_use]
    pub fn lec(&mut self) -> LecW<EscrSpec> {
        LecW::new(self, 16)
    }
    #[doc = "Bits 24:31 - Frame end delimiter code"]
    #[inline(always)]
    #[must_use]
    pub fn fec(&mut self) -> FecW<EscrSpec> {
        FecW::new(self, 24)
    }
}
#[doc = "embedded synchronization code register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`escr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`escr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EscrSpec;
impl crate::RegisterSpec for EscrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`escr::R`](R) reader structure"]
impl crate::Readable for EscrSpec {}
#[doc = "`write(|w| ..)` method takes [`escr::W`](W) writer structure"]
impl crate::Writable for EscrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ESCR to value 0"]
impl crate::Resettable for EscrSpec {
    const RESET_VALUE: u32 = 0;
}
