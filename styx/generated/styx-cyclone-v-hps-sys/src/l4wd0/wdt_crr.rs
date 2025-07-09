// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_crr` reader"]
pub type R = crate::R<WdtCrrSpec>;
#[doc = "Register `wdt_crr` writer"]
pub type W = crate::W<WdtCrrSpec>;
#[doc = "Field `wdt_crr` reader - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
pub type WdtCrrR = crate::FieldReader;
#[doc = "This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WdtCrr {
    #[doc = "118: `1110110`"]
    Kick = 118,
}
impl From<WdtCrr> for u8 {
    #[inline(always)]
    fn from(variant: WdtCrr) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for WdtCrr {
    type Ux = u8;
}
#[doc = "Field `wdt_crr` writer - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
pub type WdtCrrW<'a, REG> = crate::FieldWriter<'a, REG, 8, WdtCrr>;
impl<'a, REG> WdtCrrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1110110`"]
    #[inline(always)]
    pub fn kick(self) -> &'a mut crate::W<REG> {
        self.variant(WdtCrr::Kick)
    }
}
impl R {
    #[doc = "Bits 0:7 - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
    #[inline(always)]
    pub fn wdt_crr(&self) -> WdtCrrR {
        WdtCrrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This register is used to restart the watchdog counter. As a safety feature to prevent accidental restarts, the kick value of 0x76 must be written. A restart also clears the watchdog interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_crr(&mut self) -> WdtCrrW<WdtCrrSpec> {
        WdtCrrW::new(self, 0)
    }
}
#[doc = "Restarts the watchdog.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_crr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCrrSpec;
impl crate::RegisterSpec for WdtCrrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`write(|w| ..)` method takes [`wdt_crr::W`](W) writer structure"]
impl crate::Writable for WdtCrrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets wdt_crr to value 0"]
impl crate::Resettable for WdtCrrSpec {
    const RESET_VALUE: u32 = 0;
}
