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
#[doc = "Register `L2CKCR` reader"]
pub type R = crate::R<L2ckcrSpec>;
#[doc = "Register `L2CKCR` writer"]
pub type W = crate::W<L2ckcrSpec>;
#[doc = "Field `CKBLUE` reader - Color Key Blue value"]
pub type CkblueR = crate::FieldReader;
#[doc = "Field `CKBLUE` writer - Color Key Blue value"]
pub type CkblueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `CKGREEN` reader - Color Key Green value"]
pub type CkgreenR = crate::FieldReader;
#[doc = "Field `CKGREEN` writer - Color Key Green value"]
pub type CkgreenW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `CKRED` reader - Color Key Red value"]
pub type CkredR = crate::FieldReader<u16>;
#[doc = "Field `CKRED` writer - Color Key Red value"]
pub type CkredW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:7 - Color Key Blue value"]
    #[inline(always)]
    pub fn ckblue(&self) -> CkblueR {
        CkblueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:14 - Color Key Green value"]
    #[inline(always)]
    pub fn ckgreen(&self) -> CkgreenR {
        CkgreenR::new(((self.bits >> 8) & 0x7f) as u8)
    }
    #[doc = "Bits 15:23 - Color Key Red value"]
    #[inline(always)]
    pub fn ckred(&self) -> CkredR {
        CkredR::new(((self.bits >> 15) & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:7 - Color Key Blue value"]
    #[inline(always)]
    #[must_use]
    pub fn ckblue(&mut self) -> CkblueW<L2ckcrSpec> {
        CkblueW::new(self, 0)
    }
    #[doc = "Bits 8:14 - Color Key Green value"]
    #[inline(always)]
    #[must_use]
    pub fn ckgreen(&mut self) -> CkgreenW<L2ckcrSpec> {
        CkgreenW::new(self, 8)
    }
    #[doc = "Bits 15:23 - Color Key Red value"]
    #[inline(always)]
    #[must_use]
    pub fn ckred(&mut self) -> CkredW<L2ckcrSpec> {
        CkredW::new(self, 15)
    }
}
#[doc = "Layerx Color Keying Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2ckcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2ckcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L2ckcrSpec;
impl crate::RegisterSpec for L2ckcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 272u64;
}
#[doc = "`read()` method returns [`l2ckcr::R`](R) reader structure"]
impl crate::Readable for L2ckcrSpec {}
#[doc = "`write(|w| ..)` method takes [`l2ckcr::W`](W) writer structure"]
impl crate::Writable for L2ckcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L2CKCR to value 0"]
impl crate::Resettable for L2ckcrSpec {
    const RESET_VALUE: u32 = 0;
}
