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
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `START` reader - Start"]
pub type StartR = crate::BitReader;
#[doc = "Field `START` writer - Start"]
pub type StartW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SUSP` reader - Suspend"]
pub type SuspR = crate::BitReader;
#[doc = "Field `SUSP` writer - Suspend"]
pub type SuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ABORT` reader - Abort"]
pub type AbortR = crate::BitReader;
#[doc = "Field `ABORT` writer - Abort"]
pub type AbortW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEIE` reader - Transfer error interrupt enable"]
pub type TeieR = crate::BitReader;
#[doc = "Field `TEIE` writer - Transfer error interrupt enable"]
pub type TeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIE` reader - Transfer complete interrupt enable"]
pub type TcieR = crate::BitReader;
#[doc = "Field `TCIE` writer - Transfer complete interrupt enable"]
pub type TcieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TWIE` reader - Transfer watermark interrupt enable"]
pub type TwieR = crate::BitReader;
#[doc = "Field `TWIE` writer - Transfer watermark interrupt enable"]
pub type TwieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAEIE` reader - CLUT access error interrupt enable"]
pub type CaeieR = crate::BitReader;
#[doc = "Field `CAEIE` writer - CLUT access error interrupt enable"]
pub type CaeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIE` reader - CLUT transfer complete interrupt enable"]
pub type CtcieR = crate::BitReader;
#[doc = "Field `CTCIE` writer - CLUT transfer complete interrupt enable"]
pub type CtcieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CEIE` reader - Configuration Error Interrupt Enable"]
pub type CeieR = crate::BitReader;
#[doc = "Field `CEIE` writer - Configuration Error Interrupt Enable"]
pub type CeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MODE` reader - DMA2D mode"]
pub type ModeR = crate::FieldReader;
#[doc = "Field `MODE` writer - DMA2D mode"]
pub type ModeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Start"]
    #[inline(always)]
    pub fn start(&self) -> StartR {
        StartR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Suspend"]
    #[inline(always)]
    pub fn susp(&self) -> SuspR {
        SuspR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Abort"]
    #[inline(always)]
    pub fn abort(&self) -> AbortR {
        AbortR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 8 - Transfer error interrupt enable"]
    #[inline(always)]
    pub fn teie(&self) -> TeieR {
        TeieR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Transfer complete interrupt enable"]
    #[inline(always)]
    pub fn tcie(&self) -> TcieR {
        TcieR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Transfer watermark interrupt enable"]
    #[inline(always)]
    pub fn twie(&self) -> TwieR {
        TwieR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - CLUT access error interrupt enable"]
    #[inline(always)]
    pub fn caeie(&self) -> CaeieR {
        CaeieR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - CLUT transfer complete interrupt enable"]
    #[inline(always)]
    pub fn ctcie(&self) -> CtcieR {
        CtcieR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Configuration Error Interrupt Enable"]
    #[inline(always)]
    pub fn ceie(&self) -> CeieR {
        CeieR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 16:17 - DMA2D mode"]
    #[inline(always)]
    pub fn mode(&self) -> ModeR {
        ModeR::new(((self.bits >> 16) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Start"]
    #[inline(always)]
    #[must_use]
    pub fn start(&mut self) -> StartW<CrSpec> {
        StartW::new(self, 0)
    }
    #[doc = "Bit 1 - Suspend"]
    #[inline(always)]
    #[must_use]
    pub fn susp(&mut self) -> SuspW<CrSpec> {
        SuspW::new(self, 1)
    }
    #[doc = "Bit 2 - Abort"]
    #[inline(always)]
    #[must_use]
    pub fn abort(&mut self) -> AbortW<CrSpec> {
        AbortW::new(self, 2)
    }
    #[doc = "Bit 8 - Transfer error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn teie(&mut self) -> TeieW<CrSpec> {
        TeieW::new(self, 8)
    }
    #[doc = "Bit 9 - Transfer complete interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tcie(&mut self) -> TcieW<CrSpec> {
        TcieW::new(self, 9)
    }
    #[doc = "Bit 10 - Transfer watermark interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn twie(&mut self) -> TwieW<CrSpec> {
        TwieW::new(self, 10)
    }
    #[doc = "Bit 11 - CLUT access error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn caeie(&mut self) -> CaeieW<CrSpec> {
        CaeieW::new(self, 11)
    }
    #[doc = "Bit 12 - CLUT transfer complete interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ctcie(&mut self) -> CtcieW<CrSpec> {
        CtcieW::new(self, 12)
    }
    #[doc = "Bit 13 - Configuration Error Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn ceie(&mut self) -> CeieW<CrSpec> {
        CeieW::new(self, 13)
    }
    #[doc = "Bits 16:17 - DMA2D mode"]
    #[inline(always)]
    #[must_use]
    pub fn mode(&mut self) -> ModeW<CrSpec> {
        ModeW::new(self, 16)
    }
}
#[doc = "control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0;
}
