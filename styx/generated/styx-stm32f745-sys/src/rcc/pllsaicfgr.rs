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
#[doc = "Register `PLLSAICFGR` reader"]
pub type R = crate::R<PllsaicfgrSpec>;
#[doc = "Register `PLLSAICFGR` writer"]
pub type W = crate::W<PllsaicfgrSpec>;
#[doc = "Field `PLLSAIN` reader - PLLSAI division factor for VCO"]
pub type PllsainR = crate::FieldReader<u16>;
#[doc = "Field `PLLSAIN` writer - PLLSAI division factor for VCO"]
pub type PllsainW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `PLLSAIP` reader - PLLSAI division factor for 48MHz clock"]
pub type PllsaipR = crate::FieldReader;
#[doc = "Field `PLLSAIP` writer - PLLSAI division factor for 48MHz clock"]
pub type PllsaipW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PLLSAIQ` reader - PLLSAI division factor for SAI clock"]
pub type PllsaiqR = crate::FieldReader;
#[doc = "Field `PLLSAIQ` writer - PLLSAI division factor for SAI clock"]
pub type PllsaiqW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PLLSAIR` reader - PLLSAI division factor for LCD clock"]
pub type PllsairR = crate::FieldReader;
#[doc = "Field `PLLSAIR` writer - PLLSAI division factor for LCD clock"]
pub type PllsairW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 6:14 - PLLSAI division factor for VCO"]
    #[inline(always)]
    pub fn pllsain(&self) -> PllsainR {
        PllsainR::new(((self.bits >> 6) & 0x01ff) as u16)
    }
    #[doc = "Bits 16:17 - PLLSAI division factor for 48MHz clock"]
    #[inline(always)]
    pub fn pllsaip(&self) -> PllsaipR {
        PllsaipR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 24:27 - PLLSAI division factor for SAI clock"]
    #[inline(always)]
    pub fn pllsaiq(&self) -> PllsaiqR {
        PllsaiqR::new(((self.bits >> 24) & 0x0f) as u8)
    }
    #[doc = "Bits 28:30 - PLLSAI division factor for LCD clock"]
    #[inline(always)]
    pub fn pllsair(&self) -> PllsairR {
        PllsairR::new(((self.bits >> 28) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 6:14 - PLLSAI division factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn pllsain(&mut self) -> PllsainW<PllsaicfgrSpec> {
        PllsainW::new(self, 6)
    }
    #[doc = "Bits 16:17 - PLLSAI division factor for 48MHz clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllsaip(&mut self) -> PllsaipW<PllsaicfgrSpec> {
        PllsaipW::new(self, 16)
    }
    #[doc = "Bits 24:27 - PLLSAI division factor for SAI clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllsaiq(&mut self) -> PllsaiqW<PllsaicfgrSpec> {
        PllsaiqW::new(self, 24)
    }
    #[doc = "Bits 28:30 - PLLSAI division factor for LCD clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllsair(&mut self) -> PllsairW<PllsaicfgrSpec> {
        PllsairW::new(self, 28)
    }
}
#[doc = "PLL configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pllsaicfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pllsaicfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PllsaicfgrSpec;
impl crate::RegisterSpec for PllsaicfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`pllsaicfgr::R`](R) reader structure"]
impl crate::Readable for PllsaicfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`pllsaicfgr::W`](W) writer structure"]
impl crate::Writable for PllsaicfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PLLSAICFGR to value 0x2000_3000"]
impl crate::Resettable for PllsaicfgrSpec {
    const RESET_VALUE: u32 = 0x2000_3000;
}
