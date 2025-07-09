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
#[doc = "Register `RISR` reader"]
pub type R = crate::R<RisrSpec>;
#[doc = "Register `RISR` writer"]
pub type W = crate::W<RisrSpec>;
#[doc = "Field `INRIS` reader - Input FIFO service raw interrupt status"]
pub type InrisR = crate::BitReader;
#[doc = "Field `INRIS` writer - Input FIFO service raw interrupt status"]
pub type InrisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OUTRIS` reader - Output FIFO service raw interrupt status"]
pub type OutrisR = crate::BitReader;
#[doc = "Field `OUTRIS` writer - Output FIFO service raw interrupt status"]
pub type OutrisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Input FIFO service raw interrupt status"]
    #[inline(always)]
    pub fn inris(&self) -> InrisR {
        InrisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Output FIFO service raw interrupt status"]
    #[inline(always)]
    pub fn outris(&self) -> OutrisR {
        OutrisR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Input FIFO service raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn inris(&mut self) -> InrisW<RisrSpec> {
        InrisW::new(self, 0)
    }
    #[doc = "Bit 1 - Output FIFO service raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn outris(&mut self) -> OutrisW<RisrSpec> {
        OutrisW::new(self, 1)
    }
}
#[doc = "raw interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`risr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RisrSpec;
impl crate::RegisterSpec for RisrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`risr::R`](R) reader structure"]
impl crate::Readable for RisrSpec {}
#[doc = "`reset()` method sets RISR to value 0x01"]
impl crate::Resettable for RisrSpec {
    const RESET_VALUE: u32 = 0x01;
}
