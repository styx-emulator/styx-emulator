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
#[doc = "Register `DMAIER` reader"]
pub type R = crate::R<DmaierSpec>;
#[doc = "Register `DMAIER` writer"]
pub type W = crate::W<DmaierSpec>;
#[doc = "Field `TIE` reader - TIE"]
pub type TieR = crate::BitReader;
#[doc = "Field `TIE` writer - TIE"]
pub type TieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TPSIE` reader - TPSIE"]
pub type TpsieR = crate::BitReader;
#[doc = "Field `TPSIE` writer - TPSIE"]
pub type TpsieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TBUIE` reader - TBUIE"]
pub type TbuieR = crate::BitReader;
#[doc = "Field `TBUIE` writer - TBUIE"]
pub type TbuieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TJTIE` reader - TJTIE"]
pub type TjtieR = crate::BitReader;
#[doc = "Field `TJTIE` writer - TJTIE"]
pub type TjtieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ROIE` reader - ROIE"]
pub type RoieR = crate::BitReader;
#[doc = "Field `ROIE` writer - ROIE"]
pub type RoieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TUIE` reader - TUIE"]
pub type TuieR = crate::BitReader;
#[doc = "Field `TUIE` writer - TUIE"]
pub type TuieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RIE` reader - RIE"]
pub type RieR = crate::BitReader;
#[doc = "Field `RIE` writer - RIE"]
pub type RieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RBUIE` reader - RBUIE"]
pub type RbuieR = crate::BitReader;
#[doc = "Field `RBUIE` writer - RBUIE"]
pub type RbuieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RPSIE` reader - RPSIE"]
pub type RpsieR = crate::BitReader;
#[doc = "Field `RPSIE` writer - RPSIE"]
pub type RpsieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RWTIE` reader - RWTIE"]
pub type RwtieR = crate::BitReader;
#[doc = "Field `RWTIE` writer - RWTIE"]
pub type RwtieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETIE` reader - ETIE"]
pub type EtieR = crate::BitReader;
#[doc = "Field `ETIE` writer - ETIE"]
pub type EtieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FBEIE` reader - FBEIE"]
pub type FbeieR = crate::BitReader;
#[doc = "Field `FBEIE` writer - FBEIE"]
pub type FbeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERIE` reader - ERIE"]
pub type ErieR = crate::BitReader;
#[doc = "Field `ERIE` writer - ERIE"]
pub type ErieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AISE` reader - AISE"]
pub type AiseR = crate::BitReader;
#[doc = "Field `AISE` writer - AISE"]
pub type AiseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NISE` reader - NISE"]
pub type NiseR = crate::BitReader;
#[doc = "Field `NISE` writer - NISE"]
pub type NiseW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIE"]
    #[inline(always)]
    pub fn tie(&self) -> TieR {
        TieR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TPSIE"]
    #[inline(always)]
    pub fn tpsie(&self) -> TpsieR {
        TpsieR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - TBUIE"]
    #[inline(always)]
    pub fn tbuie(&self) -> TbuieR {
        TbuieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - TJTIE"]
    #[inline(always)]
    pub fn tjtie(&self) -> TjtieR {
        TjtieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - ROIE"]
    #[inline(always)]
    pub fn roie(&self) -> RoieR {
        RoieR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - TUIE"]
    #[inline(always)]
    pub fn tuie(&self) -> TuieR {
        TuieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - RIE"]
    #[inline(always)]
    pub fn rie(&self) -> RieR {
        RieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - RBUIE"]
    #[inline(always)]
    pub fn rbuie(&self) -> RbuieR {
        RbuieR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - RPSIE"]
    #[inline(always)]
    pub fn rpsie(&self) -> RpsieR {
        RpsieR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - RWTIE"]
    #[inline(always)]
    pub fn rwtie(&self) -> RwtieR {
        RwtieR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - ETIE"]
    #[inline(always)]
    pub fn etie(&self) -> EtieR {
        EtieR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 13 - FBEIE"]
    #[inline(always)]
    pub fn fbeie(&self) -> FbeieR {
        FbeieR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - ERIE"]
    #[inline(always)]
    pub fn erie(&self) -> ErieR {
        ErieR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - AISE"]
    #[inline(always)]
    pub fn aise(&self) -> AiseR {
        AiseR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - NISE"]
    #[inline(always)]
    pub fn nise(&self) -> NiseR {
        NiseR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIE"]
    #[inline(always)]
    #[must_use]
    pub fn tie(&mut self) -> TieW<DmaierSpec> {
        TieW::new(self, 0)
    }
    #[doc = "Bit 1 - TPSIE"]
    #[inline(always)]
    #[must_use]
    pub fn tpsie(&mut self) -> TpsieW<DmaierSpec> {
        TpsieW::new(self, 1)
    }
    #[doc = "Bit 2 - TBUIE"]
    #[inline(always)]
    #[must_use]
    pub fn tbuie(&mut self) -> TbuieW<DmaierSpec> {
        TbuieW::new(self, 2)
    }
    #[doc = "Bit 3 - TJTIE"]
    #[inline(always)]
    #[must_use]
    pub fn tjtie(&mut self) -> TjtieW<DmaierSpec> {
        TjtieW::new(self, 3)
    }
    #[doc = "Bit 4 - ROIE"]
    #[inline(always)]
    #[must_use]
    pub fn roie(&mut self) -> RoieW<DmaierSpec> {
        RoieW::new(self, 4)
    }
    #[doc = "Bit 5 - TUIE"]
    #[inline(always)]
    #[must_use]
    pub fn tuie(&mut self) -> TuieW<DmaierSpec> {
        TuieW::new(self, 5)
    }
    #[doc = "Bit 6 - RIE"]
    #[inline(always)]
    #[must_use]
    pub fn rie(&mut self) -> RieW<DmaierSpec> {
        RieW::new(self, 6)
    }
    #[doc = "Bit 7 - RBUIE"]
    #[inline(always)]
    #[must_use]
    pub fn rbuie(&mut self) -> RbuieW<DmaierSpec> {
        RbuieW::new(self, 7)
    }
    #[doc = "Bit 8 - RPSIE"]
    #[inline(always)]
    #[must_use]
    pub fn rpsie(&mut self) -> RpsieW<DmaierSpec> {
        RpsieW::new(self, 8)
    }
    #[doc = "Bit 9 - RWTIE"]
    #[inline(always)]
    #[must_use]
    pub fn rwtie(&mut self) -> RwtieW<DmaierSpec> {
        RwtieW::new(self, 9)
    }
    #[doc = "Bit 10 - ETIE"]
    #[inline(always)]
    #[must_use]
    pub fn etie(&mut self) -> EtieW<DmaierSpec> {
        EtieW::new(self, 10)
    }
    #[doc = "Bit 13 - FBEIE"]
    #[inline(always)]
    #[must_use]
    pub fn fbeie(&mut self) -> FbeieW<DmaierSpec> {
        FbeieW::new(self, 13)
    }
    #[doc = "Bit 14 - ERIE"]
    #[inline(always)]
    #[must_use]
    pub fn erie(&mut self) -> ErieW<DmaierSpec> {
        ErieW::new(self, 14)
    }
    #[doc = "Bit 15 - AISE"]
    #[inline(always)]
    #[must_use]
    pub fn aise(&mut self) -> AiseW<DmaierSpec> {
        AiseW::new(self, 15)
    }
    #[doc = "Bit 16 - NISE"]
    #[inline(always)]
    #[must_use]
    pub fn nise(&mut self) -> NiseW<DmaierSpec> {
        NiseW::new(self, 16)
    }
}
#[doc = "Ethernet DMA interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmaier::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmaier::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaierSpec;
impl crate::RegisterSpec for DmaierSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`dmaier::R`](R) reader structure"]
impl crate::Readable for DmaierSpec {}
#[doc = "`write(|w| ..)` method takes [`dmaier::W`](W) writer structure"]
impl crate::Writable for DmaierSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMAIER to value 0"]
impl crate::Resettable for DmaierSpec {
    const RESET_VALUE: u32 = 0;
}
