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
#[doc = "Register `MMCRFAECR` reader"]
pub type R = crate::R<MmcrfaecrSpec>;
#[doc = "Register `MMCRFAECR` writer"]
pub type W = crate::W<MmcrfaecrSpec>;
#[doc = "Field `RFAEC` reader - RFAEC"]
pub type RfaecR = crate::FieldReader<u32>;
#[doc = "Field `RFAEC` writer - RFAEC"]
pub type RfaecW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RFAEC"]
    #[inline(always)]
    pub fn rfaec(&self) -> RfaecR {
        RfaecR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RFAEC"]
    #[inline(always)]
    #[must_use]
    pub fn rfaec(&mut self) -> RfaecW<MmcrfaecrSpec> {
        RfaecW::new(self, 0)
    }
}
#[doc = "Ethernet MMC received frames with alignment error counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrfaecr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrfaecrSpec;
impl crate::RegisterSpec for MmcrfaecrSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`mmcrfaecr::R`](R) reader structure"]
impl crate::Readable for MmcrfaecrSpec {}
#[doc = "`reset()` method sets MMCRFAECR to value 0"]
impl crate::Resettable for MmcrfaecrSpec {
    const RESET_VALUE: u32 = 0;
}
