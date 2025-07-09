// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OR` reader"]
pub type R = crate::R<OrSpec>;
#[doc = "Register `OR` writer"]
pub type W = crate::W<OrSpec>;
#[doc = "Field `RTC_ALARM_TYPE` reader - RTC_ALARM on PC13 output type"]
pub type RtcAlarmTypeR = crate::BitReader;
#[doc = "Field `RTC_ALARM_TYPE` writer - RTC_ALARM on PC13 output type"]
pub type RtcAlarmTypeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RTC_OUT_RMP` reader - RTC_OUT remap"]
pub type RtcOutRmpR = crate::BitReader;
#[doc = "Field `RTC_OUT_RMP` writer - RTC_OUT remap"]
pub type RtcOutRmpW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - RTC_ALARM on PC13 output type"]
    #[inline(always)]
    pub fn rtc_alarm_type(&self) -> RtcAlarmTypeR {
        RtcAlarmTypeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - RTC_OUT remap"]
    #[inline(always)]
    pub fn rtc_out_rmp(&self) -> RtcOutRmpR {
        RtcOutRmpR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - RTC_ALARM on PC13 output type"]
    #[inline(always)]
    #[must_use]
    pub fn rtc_alarm_type(&mut self) -> RtcAlarmTypeW<OrSpec> {
        RtcAlarmTypeW::new(self, 0)
    }
    #[doc = "Bit 1 - RTC_OUT remap"]
    #[inline(always)]
    #[must_use]
    pub fn rtc_out_rmp(&mut self) -> RtcOutRmpW<OrSpec> {
        RtcOutRmpW::new(self, 1)
    }
}
#[doc = "option register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`or::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`or::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OrSpec;
impl crate::RegisterSpec for OrSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`or::R`](R) reader structure"]
impl crate::Readable for OrSpec {}
#[doc = "`write(|w| ..)` method takes [`or::W`](W) writer structure"]
impl crate::Writable for OrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OR to value 0"]
impl crate::Resettable for OrSpec {
    const RESET_VALUE: u32 = 0;
}
