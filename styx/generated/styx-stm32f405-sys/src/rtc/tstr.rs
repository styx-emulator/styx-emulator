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
#[doc = "Register `TSTR` reader"]
pub type R = crate::R<TstrSpec>;
#[doc = "Register `TSTR` writer"]
pub type W = crate::W<TstrSpec>;
#[doc = "Field `TAMP1E` reader - Tamper 1 detection enable"]
pub type Tamp1eR = crate::BitReader;
#[doc = "Field `TAMP1E` writer - Tamper 1 detection enable"]
pub type Tamp1eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1TRG` reader - Active level for tamper 1"]
pub type Tamp1trgR = crate::BitReader;
#[doc = "Field `TAMP1TRG` writer - Active level for tamper 1"]
pub type Tamp1trgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPIE` reader - Tamper interrupt enable"]
pub type TampieR = crate::BitReader;
#[doc = "Field `TAMPIE` writer - Tamper interrupt enable"]
pub type TampieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1INSEL` reader - TAMPER1 mapping"]
pub type Tamp1inselR = crate::BitReader;
#[doc = "Field `TAMP1INSEL` writer - TAMPER1 mapping"]
pub type Tamp1inselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSINSEL` reader - TIMESTAMP mapping"]
pub type TsinselR = crate::BitReader;
#[doc = "Field `TSINSEL` writer - TIMESTAMP mapping"]
pub type TsinselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ALARMOUTTYPE` reader - AFO_ALARM output type"]
pub type AlarmouttypeR = crate::BitReader;
#[doc = "Field `ALARMOUTTYPE` writer - AFO_ALARM output type"]
pub type AlarmouttypeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Tamper 1 detection enable"]
    #[inline(always)]
    pub fn tamp1e(&self) -> Tamp1eR {
        Tamp1eR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Active level for tamper 1"]
    #[inline(always)]
    pub fn tamp1trg(&self) -> Tamp1trgR {
        Tamp1trgR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Tamper interrupt enable"]
    #[inline(always)]
    pub fn tampie(&self) -> TampieR {
        TampieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 16 - TAMPER1 mapping"]
    #[inline(always)]
    pub fn tamp1insel(&self) -> Tamp1inselR {
        Tamp1inselR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - TIMESTAMP mapping"]
    #[inline(always)]
    pub fn tsinsel(&self) -> TsinselR {
        TsinselR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - AFO_ALARM output type"]
    #[inline(always)]
    pub fn alarmouttype(&self) -> AlarmouttypeR {
        AlarmouttypeR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Tamper 1 detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1e(&mut self) -> Tamp1eW<TstrSpec> {
        Tamp1eW::new(self, 0)
    }
    #[doc = "Bit 1 - Active level for tamper 1"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1trg(&mut self) -> Tamp1trgW<TstrSpec> {
        Tamp1trgW::new(self, 1)
    }
    #[doc = "Bit 2 - Tamper interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tampie(&mut self) -> TampieW<TstrSpec> {
        TampieW::new(self, 2)
    }
    #[doc = "Bit 16 - TAMPER1 mapping"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1insel(&mut self) -> Tamp1inselW<TstrSpec> {
        Tamp1inselW::new(self, 16)
    }
    #[doc = "Bit 17 - TIMESTAMP mapping"]
    #[inline(always)]
    #[must_use]
    pub fn tsinsel(&mut self) -> TsinselW<TstrSpec> {
        TsinselW::new(self, 17)
    }
    #[doc = "Bit 18 - AFO_ALARM output type"]
    #[inline(always)]
    #[must_use]
    pub fn alarmouttype(&mut self) -> AlarmouttypeW<TstrSpec> {
        AlarmouttypeW::new(self, 18)
    }
}
#[doc = "time stamp time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tstr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TstrSpec;
impl crate::RegisterSpec for TstrSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`tstr::R`](R) reader structure"]
impl crate::Readable for TstrSpec {}
#[doc = "`reset()` method sets TSTR to value 0"]
impl crate::Resettable for TstrSpec {
    const RESET_VALUE: u32 = 0;
}
