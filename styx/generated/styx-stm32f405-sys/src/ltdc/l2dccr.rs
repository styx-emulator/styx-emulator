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
#[doc = "Register `L2DCCR` reader"]
pub type R = crate::R<L2dccrSpec>;
#[doc = "Register `L2DCCR` writer"]
pub type W = crate::W<L2dccrSpec>;
#[doc = "Field `DCBLUE` reader - Default Color Blue"]
pub type DcblueR = crate::FieldReader;
#[doc = "Field `DCBLUE` writer - Default Color Blue"]
pub type DcblueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DCGREEN` reader - Default Color Green"]
pub type DcgreenR = crate::FieldReader;
#[doc = "Field `DCGREEN` writer - Default Color Green"]
pub type DcgreenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DCRED` reader - Default Color Red"]
pub type DcredR = crate::FieldReader;
#[doc = "Field `DCRED` writer - Default Color Red"]
pub type DcredW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `DCALPHA` reader - Default Color Alpha"]
pub type DcalphaR = crate::FieldReader;
#[doc = "Field `DCALPHA` writer - Default Color Alpha"]
pub type DcalphaW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Default Color Blue"]
    #[inline(always)]
    pub fn dcblue(&self) -> DcblueR {
        DcblueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Default Color Green"]
    #[inline(always)]
    pub fn dcgreen(&self) -> DcgreenR {
        DcgreenR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Default Color Red"]
    #[inline(always)]
    pub fn dcred(&self) -> DcredR {
        DcredR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - Default Color Alpha"]
    #[inline(always)]
    pub fn dcalpha(&self) -> DcalphaR {
        DcalphaR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Default Color Blue"]
    #[inline(always)]
    #[must_use]
    pub fn dcblue(&mut self) -> DcblueW<L2dccrSpec> {
        DcblueW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Default Color Green"]
    #[inline(always)]
    #[must_use]
    pub fn dcgreen(&mut self) -> DcgreenW<L2dccrSpec> {
        DcgreenW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Default Color Red"]
    #[inline(always)]
    #[must_use]
    pub fn dcred(&mut self) -> DcredW<L2dccrSpec> {
        DcredW::new(self, 16)
    }
    #[doc = "Bits 24:31 - Default Color Alpha"]
    #[inline(always)]
    #[must_use]
    pub fn dcalpha(&mut self) -> DcalphaW<L2dccrSpec> {
        DcalphaW::new(self, 24)
    }
}
#[doc = "Layerx Default Color Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2dccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2dccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L2dccrSpec;
impl crate::RegisterSpec for L2dccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 284u64;
}
#[doc = "`read()` method returns [`l2dccr::R`](R) reader structure"]
impl crate::Readable for L2dccrSpec {}
#[doc = "`write(|w| ..)` method takes [`l2dccr::W`](W) writer structure"]
impl crate::Writable for L2dccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L2DCCR to value 0"]
impl crate::Resettable for L2dccrSpec {
    const RESET_VALUE: u32 = 0;
}
