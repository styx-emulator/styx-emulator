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
#[doc = "Register `MMCRFCECR` reader"]
pub type R = crate::R<MmcrfcecrSpec>;
#[doc = "Register `MMCRFCECR` writer"]
pub type W = crate::W<MmcrfcecrSpec>;
#[doc = "Field `RFCFC` reader - RFCFC"]
pub type RfcfcR = crate::FieldReader<u32>;
#[doc = "Field `RFCFC` writer - RFCFC"]
pub type RfcfcW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RFCFC"]
    #[inline(always)]
    pub fn rfcfc(&self) -> RfcfcR {
        RfcfcR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RFCFC"]
    #[inline(always)]
    #[must_use]
    pub fn rfcfc(&mut self) -> RfcfcW<MmcrfcecrSpec> {
        RfcfcW::new(self, 0)
    }
}
#[doc = "Ethernet MMC received frames with CRC error counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrfcecr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrfcecrSpec;
impl crate::RegisterSpec for MmcrfcecrSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`mmcrfcecr::R`](R) reader structure"]
impl crate::Readable for MmcrfcecrSpec {}
#[doc = "`reset()` method sets MMCRFCECR to value 0"]
impl crate::Resettable for MmcrfcecrSpec {
    const RESET_VALUE: u32 = 0;
}
