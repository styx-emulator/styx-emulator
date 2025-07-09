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
#[doc = "Field `LIF` reader - Line Interrupt flag"]
pub type LifR = crate::BitReader;
#[doc = "Field `LIF` writer - Line Interrupt flag"]
pub type LifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FUIF` reader - FIFO Underrun Interrupt flag"]
pub type FuifR = crate::BitReader;
#[doc = "Field `FUIF` writer - FIFO Underrun Interrupt flag"]
pub type FuifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TERRIF` reader - Transfer Error interrupt flag"]
pub type TerrifR = crate::BitReader;
#[doc = "Field `TERRIF` writer - Transfer Error interrupt flag"]
pub type TerrifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RRIF` reader - Register Reload Interrupt Flag"]
pub type RrifR = crate::BitReader;
#[doc = "Field `RRIF` writer - Register Reload Interrupt Flag"]
pub type RrifW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Line Interrupt flag"]
    #[inline(always)]
    pub fn lif(&self) -> LifR {
        LifR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - FIFO Underrun Interrupt flag"]
    #[inline(always)]
    pub fn fuif(&self) -> FuifR {
        FuifR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transfer Error interrupt flag"]
    #[inline(always)]
    pub fn terrif(&self) -> TerrifR {
        TerrifR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Register Reload Interrupt Flag"]
    #[inline(always)]
    pub fn rrif(&self) -> RrifR {
        RrifR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Line Interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn lif(&mut self) -> LifW<IsrSpec> {
        LifW::new(self, 0)
    }
    #[doc = "Bit 1 - FIFO Underrun Interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn fuif(&mut self) -> FuifW<IsrSpec> {
        FuifW::new(self, 1)
    }
    #[doc = "Bit 2 - Transfer Error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn terrif(&mut self) -> TerrifW<IsrSpec> {
        TerrifW::new(self, 2)
    }
    #[doc = "Bit 3 - Register Reload Interrupt Flag"]
    #[inline(always)]
    #[must_use]
    pub fn rrif(&mut self) -> RrifW<IsrSpec> {
        RrifW::new(self, 3)
    }
}
#[doc = "Interrupt Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`reset()` method sets ISR to value 0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0;
}
