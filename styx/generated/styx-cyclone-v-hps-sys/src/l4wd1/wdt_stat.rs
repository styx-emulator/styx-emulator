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
#[doc = "Register `wdt_stat` reader"]
pub type R = crate::R<WdtStatSpec>;
#[doc = "Register `wdt_stat` writer"]
pub type W = crate::W<WdtStatSpec>;
#[doc = "Provides the interrupt status of the watchdog.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WdtStat {
    #[doc = "1: `1`"]
    Active = 1,
    #[doc = "0: `0`"]
    Inactive = 0,
}
impl From<WdtStat> for bool {
    #[inline(always)]
    fn from(variant: WdtStat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wdt_stat` reader - Provides the interrupt status of the watchdog."]
pub type WdtStatR = crate::BitReader<WdtStat>;
impl WdtStatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> WdtStat {
        match self.bits {
            true => WdtStat::Active,
            false => WdtStat::Inactive,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == WdtStat::Active
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == WdtStat::Inactive
    }
}
#[doc = "Field `wdt_stat` writer - Provides the interrupt status of the watchdog."]
pub type WdtStatW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Provides the interrupt status of the watchdog."]
    #[inline(always)]
    pub fn wdt_stat(&self) -> WdtStatR {
        WdtStatR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Provides the interrupt status of the watchdog."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_stat(&mut self) -> WdtStatW<WdtStatSpec> {
        WdtStatW::new(self, 0)
    }
}
#[doc = "Provides interrupt status\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_stat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtStatSpec;
impl crate::RegisterSpec for WdtStatSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`wdt_stat::R`](R) reader structure"]
impl crate::Readable for WdtStatSpec {}
#[doc = "`reset()` method sets wdt_stat to value 0"]
impl crate::Resettable for WdtStatSpec {
    const RESET_VALUE: u32 = 0;
}
