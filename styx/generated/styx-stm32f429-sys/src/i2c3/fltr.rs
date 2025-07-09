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
#[doc = "Register `FLTR` reader"]
pub type R = crate::R<FltrSpec>;
#[doc = "Register `FLTR` writer"]
pub type W = crate::W<FltrSpec>;
#[doc = "Field `DNF` reader - Digital noise filter"]
pub type DnfR = crate::FieldReader;
#[doc = "Field `DNF` writer - Digital noise filter"]
pub type DnfW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `ANOFF` reader - Analog noise filter OFF"]
pub type AnoffR = crate::BitReader;
#[doc = "Field `ANOFF` writer - Analog noise filter OFF"]
pub type AnoffW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:3 - Digital noise filter"]
    #[inline(always)]
    pub fn dnf(&self) -> DnfR {
        DnfR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 4 - Analog noise filter OFF"]
    #[inline(always)]
    pub fn anoff(&self) -> AnoffR {
        AnoffR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:3 - Digital noise filter"]
    #[inline(always)]
    #[must_use]
    pub fn dnf(&mut self) -> DnfW<FltrSpec> {
        DnfW::new(self, 0)
    }
    #[doc = "Bit 4 - Analog noise filter OFF"]
    #[inline(always)]
    #[must_use]
    pub fn anoff(&mut self) -> AnoffW<FltrSpec> {
        AnoffW::new(self, 4)
    }
}
#[doc = "I2C FLTR register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fltr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fltr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FltrSpec;
impl crate::RegisterSpec for FltrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`fltr::R`](R) reader structure"]
impl crate::Readable for FltrSpec {}
#[doc = "`write(|w| ..)` method takes [`fltr::W`](W) writer structure"]
impl crate::Writable for FltrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FLTR to value 0"]
impl crate::Resettable for FltrSpec {
    const RESET_VALUE: u32 = 0;
}
