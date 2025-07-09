// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_eoi` reader"]
pub type R = crate::R<WdtEoiSpec>;
#[doc = "Register `wdt_eoi` writer"]
pub type W = crate::W<WdtEoiSpec>;
#[doc = "Field `wdt_eoi` reader - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
pub type WdtEoiR = crate::BitReader;
#[doc = "Field `wdt_eoi` writer - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
pub type WdtEoiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
    #[inline(always)]
    pub fn wdt_eoi(&self) -> WdtEoiR {
        WdtEoiR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_eoi(&mut self) -> WdtEoiW<WdtEoiSpec> {
        WdtEoiW::new(self, 0)
    }
}
#[doc = "Clears the watchdog interrupt when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_eoi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtEoiSpec;
impl crate::RegisterSpec for WdtEoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`wdt_eoi::R`](R) reader structure"]
impl crate::Readable for WdtEoiSpec {}
#[doc = "`reset()` method sets wdt_eoi to value 0"]
impl crate::Resettable for WdtEoiSpec {
    const RESET_VALUE: u32 = 0;
}
