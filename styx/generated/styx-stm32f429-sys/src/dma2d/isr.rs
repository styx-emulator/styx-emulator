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
#[doc = "Register `ISR` reader"]
pub type R = crate::R<IsrSpec>;
#[doc = "Register `ISR` writer"]
pub type W = crate::W<IsrSpec>;
#[doc = "Field `TEIF` reader - Transfer error interrupt flag"]
pub type TeifR = crate::BitReader;
#[doc = "Field `TEIF` writer - Transfer error interrupt flag"]
pub type TeifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIF` reader - Transfer complete interrupt flag"]
pub type TcifR = crate::BitReader;
#[doc = "Field `TCIF` writer - Transfer complete interrupt flag"]
pub type TcifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TWIF` reader - Transfer watermark interrupt flag"]
pub type TwifR = crate::BitReader;
#[doc = "Field `TWIF` writer - Transfer watermark interrupt flag"]
pub type TwifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAEIF` reader - CLUT access error interrupt flag"]
pub type CaeifR = crate::BitReader;
#[doc = "Field `CAEIF` writer - CLUT access error interrupt flag"]
pub type CaeifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF` reader - CLUT transfer complete interrupt flag"]
pub type CtcifR = crate::BitReader;
#[doc = "Field `CTCIF` writer - CLUT transfer complete interrupt flag"]
pub type CtcifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CEIF` reader - Configuration error interrupt flag"]
pub type CeifR = crate::BitReader;
#[doc = "Field `CEIF` writer - Configuration error interrupt flag"]
pub type CeifW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Transfer error interrupt flag"]
    #[inline(always)]
    pub fn teif(&self) -> TeifR {
        TeifR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Transfer complete interrupt flag"]
    #[inline(always)]
    pub fn tcif(&self) -> TcifR {
        TcifR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transfer watermark interrupt flag"]
    #[inline(always)]
    pub fn twif(&self) -> TwifR {
        TwifR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - CLUT access error interrupt flag"]
    #[inline(always)]
    pub fn caeif(&self) -> CaeifR {
        CaeifR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - CLUT transfer complete interrupt flag"]
    #[inline(always)]
    pub fn ctcif(&self) -> CtcifR {
        CtcifR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Configuration error interrupt flag"]
    #[inline(always)]
    pub fn ceif(&self) -> CeifR {
        CeifR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn teif(&mut self) -> TeifW<IsrSpec> {
        TeifW::new(self, 0)
    }
    #[doc = "Bit 1 - Transfer complete interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn tcif(&mut self) -> TcifW<IsrSpec> {
        TcifW::new(self, 1)
    }
    #[doc = "Bit 2 - Transfer watermark interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn twif(&mut self) -> TwifW<IsrSpec> {
        TwifW::new(self, 2)
    }
    #[doc = "Bit 3 - CLUT access error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn caeif(&mut self) -> CaeifW<IsrSpec> {
        CaeifW::new(self, 3)
    }
    #[doc = "Bit 4 - CLUT transfer complete interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif(&mut self) -> CtcifW<IsrSpec> {
        CtcifW::new(self, 4)
    }
    #[doc = "Bit 5 - Configuration error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn ceif(&mut self) -> CeifW<IsrSpec> {
        CeifW::new(self, 5)
    }
}
#[doc = "Interrupt Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`reset()` method sets ISR to value 0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0;
}
