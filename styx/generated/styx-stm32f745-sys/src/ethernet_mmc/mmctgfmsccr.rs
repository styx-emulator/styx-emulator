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
#[doc = "Register `MMCTGFMSCCR` reader"]
pub type R = crate::R<MmctgfmsccrSpec>;
#[doc = "Register `MMCTGFMSCCR` writer"]
pub type W = crate::W<MmctgfmsccrSpec>;
#[doc = "Field `TGFMSCC` reader - TGFMSCC"]
pub type TgfmsccR = crate::FieldReader<u32>;
#[doc = "Field `TGFMSCC` writer - TGFMSCC"]
pub type TgfmsccW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TGFMSCC"]
    #[inline(always)]
    pub fn tgfmscc(&self) -> TgfmsccR {
        TgfmsccR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TGFMSCC"]
    #[inline(always)]
    #[must_use]
    pub fn tgfmscc(&mut self) -> TgfmsccW<MmctgfmsccrSpec> {
        TgfmsccW::new(self, 0)
    }
}
#[doc = "Ethernet MMC transmitted good frames after more than a single collision\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctgfmsccr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctgfmsccrSpec;
impl crate::RegisterSpec for MmctgfmsccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`mmctgfmsccr::R`](R) reader structure"]
impl crate::Readable for MmctgfmsccrSpec {}
#[doc = "`reset()` method sets MMCTGFMSCCR to value 0"]
impl crate::Resettable for MmctgfmsccrSpec {
    const RESET_VALUE: u32 = 0;
}
