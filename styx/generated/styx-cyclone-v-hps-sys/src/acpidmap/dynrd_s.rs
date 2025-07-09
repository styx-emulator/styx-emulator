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
#[doc = "Register `dynrd_s` reader"]
pub type R = crate::R<DynrdSSpec>;
#[doc = "Register `dynrd_s` writer"]
pub type W = crate::W<DynrdSSpec>;
#[doc = "Field `user` reader - This value is propagated to SCU as ARUSERS."]
pub type UserR = crate::FieldReader;
#[doc = "Field `user` writer - This value is propagated to SCU as ARUSERS."]
pub type UserW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `page` reader - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageR = crate::FieldReader;
#[doc = "Field `page` writer - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 4:8 - This value is propagated to SCU as ARUSERS."]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 12:13 - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    pub fn page(&self) -> PageR {
        PageR::new(((self.bits >> 12) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 4:8 - This value is propagated to SCU as ARUSERS."]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<DynrdSSpec> {
        UserW::new(self, 4)
    }
    #[doc = "Bits 12:13 - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    #[must_use]
    pub fn page(&mut self) -> PageW<DynrdSSpec> {
        PageW::new(self, 12)
    }
}
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynrd_s::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DynrdSSpec;
impl crate::RegisterSpec for DynrdSSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`dynrd_s::R`](R) reader structure"]
impl crate::Readable for DynrdSSpec {}
#[doc = "`reset()` method sets dynrd_s to value 0"]
impl crate::Resettable for DynrdSSpec {
    const RESET_VALUE: u32 = 0;
}
