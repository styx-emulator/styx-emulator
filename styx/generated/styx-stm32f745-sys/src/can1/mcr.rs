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
#[doc = "Register `MCR` reader"]
pub type R = crate::R<McrSpec>;
#[doc = "Register `MCR` writer"]
pub type W = crate::W<McrSpec>;
#[doc = "Field `INRQ` reader - INRQ"]
pub type InrqR = crate::BitReader;
#[doc = "Field `INRQ` writer - INRQ"]
pub type InrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SLEEP` reader - SLEEP"]
pub type SleepR = crate::BitReader;
#[doc = "Field `SLEEP` writer - SLEEP"]
pub type SleepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFP` reader - TXFP"]
pub type TxfpR = crate::BitReader;
#[doc = "Field `TXFP` writer - TXFP"]
pub type TxfpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFLM` reader - RFLM"]
pub type RflmR = crate::BitReader;
#[doc = "Field `RFLM` writer - RFLM"]
pub type RflmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NART` reader - NART"]
pub type NartR = crate::BitReader;
#[doc = "Field `NART` writer - NART"]
pub type NartW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AWUM` reader - AWUM"]
pub type AwumR = crate::BitReader;
#[doc = "Field `AWUM` writer - AWUM"]
pub type AwumW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ABOM` reader - ABOM"]
pub type AbomR = crate::BitReader;
#[doc = "Field `ABOM` writer - ABOM"]
pub type AbomW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TTCM` reader - TTCM"]
pub type TtcmR = crate::BitReader;
#[doc = "Field `TTCM` writer - TTCM"]
pub type TtcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RESET` reader - RESET"]
pub type ResetR = crate::BitReader;
#[doc = "Field `RESET` writer - RESET"]
pub type ResetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBF` reader - DBF"]
pub type DbfR = crate::BitReader;
#[doc = "Field `DBF` writer - DBF"]
pub type DbfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - INRQ"]
    #[inline(always)]
    pub fn inrq(&self) -> InrqR {
        InrqR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - SLEEP"]
    #[inline(always)]
    pub fn sleep(&self) -> SleepR {
        SleepR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - TXFP"]
    #[inline(always)]
    pub fn txfp(&self) -> TxfpR {
        TxfpR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - RFLM"]
    #[inline(always)]
    pub fn rflm(&self) -> RflmR {
        RflmR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - NART"]
    #[inline(always)]
    pub fn nart(&self) -> NartR {
        NartR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - AWUM"]
    #[inline(always)]
    pub fn awum(&self) -> AwumR {
        AwumR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - ABOM"]
    #[inline(always)]
    pub fn abom(&self) -> AbomR {
        AbomR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - TTCM"]
    #[inline(always)]
    pub fn ttcm(&self) -> TtcmR {
        TtcmR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 15 - RESET"]
    #[inline(always)]
    pub fn reset(&self) -> ResetR {
        ResetR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - DBF"]
    #[inline(always)]
    pub fn dbf(&self) -> DbfR {
        DbfR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - INRQ"]
    #[inline(always)]
    #[must_use]
    pub fn inrq(&mut self) -> InrqW<McrSpec> {
        InrqW::new(self, 0)
    }
    #[doc = "Bit 1 - SLEEP"]
    #[inline(always)]
    #[must_use]
    pub fn sleep(&mut self) -> SleepW<McrSpec> {
        SleepW::new(self, 1)
    }
    #[doc = "Bit 2 - TXFP"]
    #[inline(always)]
    #[must_use]
    pub fn txfp(&mut self) -> TxfpW<McrSpec> {
        TxfpW::new(self, 2)
    }
    #[doc = "Bit 3 - RFLM"]
    #[inline(always)]
    #[must_use]
    pub fn rflm(&mut self) -> RflmW<McrSpec> {
        RflmW::new(self, 3)
    }
    #[doc = "Bit 4 - NART"]
    #[inline(always)]
    #[must_use]
    pub fn nart(&mut self) -> NartW<McrSpec> {
        NartW::new(self, 4)
    }
    #[doc = "Bit 5 - AWUM"]
    #[inline(always)]
    #[must_use]
    pub fn awum(&mut self) -> AwumW<McrSpec> {
        AwumW::new(self, 5)
    }
    #[doc = "Bit 6 - ABOM"]
    #[inline(always)]
    #[must_use]
    pub fn abom(&mut self) -> AbomW<McrSpec> {
        AbomW::new(self, 6)
    }
    #[doc = "Bit 7 - TTCM"]
    #[inline(always)]
    #[must_use]
    pub fn ttcm(&mut self) -> TtcmW<McrSpec> {
        TtcmW::new(self, 7)
    }
    #[doc = "Bit 15 - RESET"]
    #[inline(always)]
    #[must_use]
    pub fn reset(&mut self) -> ResetW<McrSpec> {
        ResetW::new(self, 15)
    }
    #[doc = "Bit 16 - DBF"]
    #[inline(always)]
    #[must_use]
    pub fn dbf(&mut self) -> DbfW<McrSpec> {
        DbfW::new(self, 16)
    }
}
#[doc = "master control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct McrSpec;
impl crate::RegisterSpec for McrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`mcr::R`](R) reader structure"]
impl crate::Readable for McrSpec {}
#[doc = "`write(|w| ..)` method takes [`mcr::W`](W) writer structure"]
impl crate::Writable for McrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MCR to value 0x0001_0002"]
impl crate::Resettable for McrSpec {
    const RESET_VALUE: u32 = 0x0001_0002;
}
