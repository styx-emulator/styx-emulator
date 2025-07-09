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
#[doc = "Register `CSR` reader"]
pub type R = crate::R<CsrSpec>;
#[doc = "Register `CSR` writer"]
pub type W = crate::W<CsrSpec>;
#[doc = "Field `USR` reader - User data information"]
pub type UsrR = crate::FieldReader<u16>;
#[doc = "Field `USR` writer - User data information"]
pub type UsrW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `CS` reader - Channel A status information"]
pub type CsR = crate::FieldReader;
#[doc = "Field `CS` writer - Channel A status information"]
pub type CsW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `SOB` reader - Start Of Block"]
pub type SobR = crate::BitReader;
#[doc = "Field `SOB` writer - Start Of Block"]
pub type SobW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - User data information"]
    #[inline(always)]
    pub fn usr(&self) -> UsrR {
        UsrR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:23 - Channel A status information"]
    #[inline(always)]
    pub fn cs(&self) -> CsR {
        CsR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bit 24 - Start Of Block"]
    #[inline(always)]
    pub fn sob(&self) -> SobR {
        SobR::new(((self.bits >> 24) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - User data information"]
    #[inline(always)]
    #[must_use]
    pub fn usr(&mut self) -> UsrW<CsrSpec> {
        UsrW::new(self, 0)
    }
    #[doc = "Bits 16:23 - Channel A status information"]
    #[inline(always)]
    #[must_use]
    pub fn cs(&mut self) -> CsW<CsrSpec> {
        CsW::new(self, 16)
    }
    #[doc = "Bit 24 - Start Of Block"]
    #[inline(always)]
    #[must_use]
    pub fn sob(&mut self) -> SobW<CsrSpec> {
        SobW::new(self, 24)
    }
}
#[doc = "Channel Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CsrSpec;
impl crate::RegisterSpec for CsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`csr::R`](R) reader structure"]
impl crate::Readable for CsrSpec {}
#[doc = "`reset()` method sets CSR to value 0"]
impl crate::Resettable for CsrSpec {
    const RESET_VALUE: u32 = 0;
}
