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
#[doc = "Register `RTOR` reader"]
pub type R = crate::R<RtorSpec>;
#[doc = "Register `RTOR` writer"]
pub type W = crate::W<RtorSpec>;
#[doc = "Field `RTO` reader - Receiver timeout value"]
pub type RtoR = crate::FieldReader<u32>;
#[doc = "Field `RTO` writer - Receiver timeout value"]
pub type RtoW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
#[doc = "Field `BLEN` reader - Block Length"]
pub type BlenR = crate::FieldReader;
#[doc = "Field `BLEN` writer - Block Length"]
pub type BlenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:23 - Receiver timeout value"]
    #[inline(always)]
    pub fn rto(&self) -> RtoR {
        RtoR::new(self.bits & 0x00ff_ffff)
    }
    #[doc = "Bits 24:31 - Block Length"]
    #[inline(always)]
    pub fn blen(&self) -> BlenR {
        BlenR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:23 - Receiver timeout value"]
    #[inline(always)]
    #[must_use]
    pub fn rto(&mut self) -> RtoW<RtorSpec> {
        RtoW::new(self, 0)
    }
    #[doc = "Bits 24:31 - Block Length"]
    #[inline(always)]
    #[must_use]
    pub fn blen(&mut self) -> BlenW<RtorSpec> {
        BlenW::new(self, 24)
    }
}
#[doc = "Receiver timeout register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rtor::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rtor::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RtorSpec;
impl crate::RegisterSpec for RtorSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`rtor::R`](R) reader structure"]
impl crate::Readable for RtorSpec {}
#[doc = "`write(|w| ..)` method takes [`rtor::W`](W) writer structure"]
impl crate::Writable for RtorSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RTOR to value 0"]
impl crate::Resettable for RtorSpec {
    const RESET_VALUE: u32 = 0;
}
