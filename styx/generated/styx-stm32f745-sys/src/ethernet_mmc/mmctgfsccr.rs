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
#[doc = "Register `MMCTGFSCCR` reader"]
pub type R = crate::R<MmctgfsccrSpec>;
#[doc = "Register `MMCTGFSCCR` writer"]
pub type W = crate::W<MmctgfsccrSpec>;
#[doc = "Field `TGFSCC` reader - TGFSCC"]
pub type TgfsccR = crate::FieldReader<u32>;
#[doc = "Field `TGFSCC` writer - TGFSCC"]
pub type TgfsccW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TGFSCC"]
    #[inline(always)]
    pub fn tgfscc(&self) -> TgfsccR {
        TgfsccR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TGFSCC"]
    #[inline(always)]
    #[must_use]
    pub fn tgfscc(&mut self) -> TgfsccW<MmctgfsccrSpec> {
        TgfsccW::new(self, 0)
    }
}
#[doc = "Ethernet MMC transmitted good frames after a single collision counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctgfsccr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctgfsccrSpec;
impl crate::RegisterSpec for MmctgfsccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`mmctgfsccr::R`](R) reader structure"]
impl crate::Readable for MmctgfsccrSpec {}
#[doc = "`reset()` method sets MMCTGFSCCR to value 0"]
impl crate::Resettable for MmctgfsccrSpec {
    const RESET_VALUE: u32 = 0;
}
