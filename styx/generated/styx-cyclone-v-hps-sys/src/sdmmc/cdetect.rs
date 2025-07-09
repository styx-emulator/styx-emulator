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
#[doc = "Register `cdetect` reader"]
pub type R = crate::R<CdetectSpec>;
#[doc = "Register `cdetect` writer"]
pub type W = crate::W<CdetectSpec>;
#[doc = "Value on sdmmc_cd_i input port.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardDetectN {
    #[doc = "1: `1`"]
    Notdetected = 1,
    #[doc = "0: `0`"]
    Detected = 0,
}
impl From<CardDetectN> for bool {
    #[inline(always)]
    fn from(variant: CardDetectN) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `card_detect_n` reader - Value on sdmmc_cd_i input port."]
pub type CardDetectNR = crate::BitReader<CardDetectN>;
impl CardDetectNR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CardDetectN {
        match self.bits {
            true => CardDetectN::Notdetected,
            false => CardDetectN::Detected,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notdetected(&self) -> bool {
        *self == CardDetectN::Notdetected
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_detected(&self) -> bool {
        *self == CardDetectN::Detected
    }
}
#[doc = "Field `card_detect_n` writer - Value on sdmmc_cd_i input port."]
pub type CardDetectNW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Value on sdmmc_cd_i input port."]
    #[inline(always)]
    pub fn card_detect_n(&self) -> CardDetectNR {
        CardDetectNR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Value on sdmmc_cd_i input port."]
    #[inline(always)]
    #[must_use]
    pub fn card_detect_n(&mut self) -> CardDetectNW<CdetectSpec> {
        CardDetectNW::new(self, 0)
    }
}
#[doc = "Determines if card is present.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cdetect::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CdetectSpec;
impl crate::RegisterSpec for CdetectSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`cdetect::R`](R) reader structure"]
impl crate::Readable for CdetectSpec {}
#[doc = "`reset()` method sets cdetect to value 0x01"]
impl crate::Resettable for CdetectSpec {
    const RESET_VALUE: u32 = 0x01;
}
