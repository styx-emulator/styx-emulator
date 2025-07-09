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
#[doc = "Register `SDSR` reader"]
pub type R = crate::R<SdsrSpec>;
#[doc = "Register `SDSR` writer"]
pub type W = crate::W<SdsrSpec>;
#[doc = "Field `RE` reader - Refresh error flag"]
pub type ReR = crate::BitReader;
#[doc = "Field `RE` writer - Refresh error flag"]
pub type ReW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MODES1` reader - Status Mode for Bank 1"]
pub type Modes1R = crate::FieldReader;
#[doc = "Field `MODES1` writer - Status Mode for Bank 1"]
pub type Modes1W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MODES2` reader - Status Mode for Bank 2"]
pub type Modes2R = crate::FieldReader;
#[doc = "Field `MODES2` writer - Status Mode for Bank 2"]
pub type Modes2W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `BUSY` reader - Busy status"]
pub type BusyR = crate::BitReader;
#[doc = "Field `BUSY` writer - Busy status"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Refresh error flag"]
    #[inline(always)]
    pub fn re(&self) -> ReR {
        ReR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Status Mode for Bank 1"]
    #[inline(always)]
    pub fn modes1(&self) -> Modes1R {
        Modes1R::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bits 3:4 - Status Mode for Bank 2"]
    #[inline(always)]
    pub fn modes2(&self) -> Modes2R {
        Modes2R::new(((self.bits >> 3) & 3) as u8)
    }
    #[doc = "Bit 5 - Busy status"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Refresh error flag"]
    #[inline(always)]
    #[must_use]
    pub fn re(&mut self) -> ReW<SdsrSpec> {
        ReW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Status Mode for Bank 1"]
    #[inline(always)]
    #[must_use]
    pub fn modes1(&mut self) -> Modes1W<SdsrSpec> {
        Modes1W::new(self, 1)
    }
    #[doc = "Bits 3:4 - Status Mode for Bank 2"]
    #[inline(always)]
    #[must_use]
    pub fn modes2(&mut self) -> Modes2W<SdsrSpec> {
        Modes2W::new(self, 3)
    }
    #[doc = "Bit 5 - Busy status"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<SdsrSpec> {
        BusyW::new(self, 5)
    }
}
#[doc = "SDRAM Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdsr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdsrSpec;
impl crate::RegisterSpec for SdsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 344u64;
}
#[doc = "`read()` method returns [`sdsr::R`](R) reader structure"]
impl crate::Readable for SdsrSpec {}
#[doc = "`reset()` method sets SDSR to value 0"]
impl crate::Resettable for SdsrSpec {
    const RESET_VALUE: u32 = 0;
}
