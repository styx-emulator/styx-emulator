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
#[doc = "Register `CDSR` reader"]
pub type R = crate::R<CdsrSpec>;
#[doc = "Register `CDSR` writer"]
pub type W = crate::W<CdsrSpec>;
#[doc = "Field `VDES` reader - Vertical Data Enable display Status"]
pub type VdesR = crate::BitReader;
#[doc = "Field `VDES` writer - Vertical Data Enable display Status"]
pub type VdesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HDES` reader - Horizontal Data Enable display Status"]
pub type HdesR = crate::BitReader;
#[doc = "Field `HDES` writer - Horizontal Data Enable display Status"]
pub type HdesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSYNCS` reader - Vertical Synchronization display Status"]
pub type VsyncsR = crate::BitReader;
#[doc = "Field `VSYNCS` writer - Vertical Synchronization display Status"]
pub type VsyncsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSYNCS` reader - Horizontal Synchronization display Status"]
pub type HsyncsR = crate::BitReader;
#[doc = "Field `HSYNCS` writer - Horizontal Synchronization display Status"]
pub type HsyncsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Vertical Data Enable display Status"]
    #[inline(always)]
    pub fn vdes(&self) -> VdesR {
        VdesR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Horizontal Data Enable display Status"]
    #[inline(always)]
    pub fn hdes(&self) -> HdesR {
        HdesR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Vertical Synchronization display Status"]
    #[inline(always)]
    pub fn vsyncs(&self) -> VsyncsR {
        VsyncsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Horizontal Synchronization display Status"]
    #[inline(always)]
    pub fn hsyncs(&self) -> HsyncsR {
        HsyncsR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Vertical Data Enable display Status"]
    #[inline(always)]
    #[must_use]
    pub fn vdes(&mut self) -> VdesW<CdsrSpec> {
        VdesW::new(self, 0)
    }
    #[doc = "Bit 1 - Horizontal Data Enable display Status"]
    #[inline(always)]
    #[must_use]
    pub fn hdes(&mut self) -> HdesW<CdsrSpec> {
        HdesW::new(self, 1)
    }
    #[doc = "Bit 2 - Vertical Synchronization display Status"]
    #[inline(always)]
    #[must_use]
    pub fn vsyncs(&mut self) -> VsyncsW<CdsrSpec> {
        VsyncsW::new(self, 2)
    }
    #[doc = "Bit 3 - Horizontal Synchronization display Status"]
    #[inline(always)]
    #[must_use]
    pub fn hsyncs(&mut self) -> HsyncsW<CdsrSpec> {
        HsyncsW::new(self, 3)
    }
}
#[doc = "Current Display Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cdsr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CdsrSpec;
impl crate::RegisterSpec for CdsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`cdsr::R`](R) reader structure"]
impl crate::Readable for CdsrSpec {}
#[doc = "`reset()` method sets CDSR to value 0x0f"]
impl crate::Resettable for CdsrSpec {
    const RESET_VALUE: u32 = 0x0f;
}
