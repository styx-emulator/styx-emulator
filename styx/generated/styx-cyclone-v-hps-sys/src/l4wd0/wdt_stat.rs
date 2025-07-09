// SPDX-License-Identifier: BSD-2-Clause
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
