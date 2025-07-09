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
#[doc = "Register `SAI_ASR` reader"]
pub type R = crate::R<SaiAsrSpec>;
#[doc = "Register `SAI_ASR` writer"]
pub type W = crate::W<SaiAsrSpec>;
#[doc = "Field `OVRUDR` reader - Overrun / underrun"]
pub type OvrudrR = crate::BitReader;
#[doc = "Field `OVRUDR` writer - Overrun / underrun"]
pub type OvrudrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTEDET` reader - Mute detection"]
pub type MutedetR = crate::BitReader;
#[doc = "Field `MUTEDET` writer - Mute detection"]
pub type MutedetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WCKCFG` reader - Wrong clock configuration flag"]
pub type WckcfgR = crate::BitReader;
#[doc = "Field `WCKCFG` writer - Wrong clock configuration flag"]
pub type WckcfgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FREQ` reader - FIFO request"]
pub type FreqR = crate::BitReader;
#[doc = "Field `FREQ` writer - FIFO request"]
pub type FreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CNRDY` reader - Codec not ready"]
pub type CnrdyR = crate::BitReader;
#[doc = "Field `CNRDY` writer - Codec not ready"]
pub type CnrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AFSDET` reader - Anticipated frame synchronization detection"]
pub type AfsdetR = crate::BitReader;
#[doc = "Field `AFSDET` writer - Anticipated frame synchronization detection"]
pub type AfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LFSDET` reader - Late frame synchronization detection"]
pub type LfsdetR = crate::BitReader;
#[doc = "Field `LFSDET` writer - Late frame synchronization detection"]
pub type LfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FLTH` reader - FIFO level threshold"]
pub type FlthR = crate::FieldReader;
#[doc = "Field `FLTH` writer - FIFO level threshold"]
pub type FlthW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bit 0 - Overrun / underrun"]
    #[inline(always)]
    pub fn ovrudr(&self) -> OvrudrR {
        OvrudrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mute detection"]
    #[inline(always)]
    pub fn mutedet(&self) -> MutedetR {
        MutedetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Wrong clock configuration flag"]
    #[inline(always)]
    pub fn wckcfg(&self) -> WckcfgR {
        WckcfgR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - FIFO request"]
    #[inline(always)]
    pub fn freq(&self) -> FreqR {
        FreqR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Codec not ready"]
    #[inline(always)]
    pub fn cnrdy(&self) -> CnrdyR {
        CnrdyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Anticipated frame synchronization detection"]
    #[inline(always)]
    pub fn afsdet(&self) -> AfsdetR {
        AfsdetR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Late frame synchronization detection"]
    #[inline(always)]
    pub fn lfsdet(&self) -> LfsdetR {
        LfsdetR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 16:18 - FIFO level threshold"]
    #[inline(always)]
    pub fn flth(&self) -> FlthR {
        FlthR::new(((self.bits >> 16) & 7) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Overrun / underrun"]
    #[inline(always)]
    #[must_use]
    pub fn ovrudr(&mut self) -> OvrudrW<SaiAsrSpec> {
        OvrudrW::new(self, 0)
    }
    #[doc = "Bit 1 - Mute detection"]
    #[inline(always)]
    #[must_use]
    pub fn mutedet(&mut self) -> MutedetW<SaiAsrSpec> {
        MutedetW::new(self, 1)
    }
    #[doc = "Bit 2 - Wrong clock configuration flag"]
    #[inline(always)]
    #[must_use]
    pub fn wckcfg(&mut self) -> WckcfgW<SaiAsrSpec> {
        WckcfgW::new(self, 2)
    }
    #[doc = "Bit 3 - FIFO request"]
    #[inline(always)]
    #[must_use]
    pub fn freq(&mut self) -> FreqW<SaiAsrSpec> {
        FreqW::new(self, 3)
    }
    #[doc = "Bit 4 - Codec not ready"]
    #[inline(always)]
    #[must_use]
    pub fn cnrdy(&mut self) -> CnrdyW<SaiAsrSpec> {
        CnrdyW::new(self, 4)
    }
    #[doc = "Bit 5 - Anticipated frame synchronization detection"]
    #[inline(always)]
    #[must_use]
    pub fn afsdet(&mut self) -> AfsdetW<SaiAsrSpec> {
        AfsdetW::new(self, 5)
    }
    #[doc = "Bit 6 - Late frame synchronization detection"]
    #[inline(always)]
    #[must_use]
    pub fn lfsdet(&mut self) -> LfsdetW<SaiAsrSpec> {
        LfsdetW::new(self, 6)
    }
    #[doc = "Bits 16:18 - FIFO level threshold"]
    #[inline(always)]
    #[must_use]
    pub fn flth(&mut self) -> FlthW<SaiAsrSpec> {
        FlthW::new(self, 16)
    }
}
#[doc = "SAI AStatus register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_asr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiAsrSpec;
impl crate::RegisterSpec for SaiAsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`sai_asr::R`](R) reader structure"]
impl crate::Readable for SaiAsrSpec {}
#[doc = "`reset()` method sets SAI_ASR to value 0x08"]
impl crate::Resettable for SaiAsrSpec {
    const RESET_VALUE: u32 = 0x08;
}
