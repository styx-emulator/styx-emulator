// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_watchdog_reset_count` reader"]
pub type R = crate::R<ConfigWatchdogResetCountSpec>;
#[doc = "Register `config_watchdog_reset_count` writer"]
pub type W = crate::W<ConfigWatchdogResetCountSpec>;
#[doc = "Field `value` reader - The controller waits for this number of cycles before issuing a watchdog timeout interrupt. The value in this register is multiplied internally by 32 in the controller to form the final watchdog counter."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - The controller waits for this number of cycles before issuing a watchdog timeout interrupt. The value in this register is multiplied internally by 32 in the controller to form the final watchdog counter."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - The controller waits for this number of cycles before issuing a watchdog timeout interrupt. The value in this register is multiplied internally by 32 in the controller to form the final watchdog counter."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - The controller waits for this number of cycles before issuing a watchdog timeout interrupt. The value in this register is multiplied internally by 32 in the controller to form the final watchdog counter."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigWatchdogResetCountSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "The number of cycles the controller waits before flagging a watchdog timeout interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_watchdog_reset_count::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_watchdog_reset_count::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigWatchdogResetCountSpec;
impl crate::RegisterSpec for ConfigWatchdogResetCountSpec {
    type Ux = u32;
    const OFFSET: u64 = 688u64;
}
#[doc = "`read()` method returns [`config_watchdog_reset_count::R`](R) reader structure"]
impl crate::Readable for ConfigWatchdogResetCountSpec {}
#[doc = "`write(|w| ..)` method takes [`config_watchdog_reset_count::W`](W) writer structure"]
impl crate::Writable for ConfigWatchdogResetCountSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_watchdog_reset_count to value 0x5b9a"]
impl crate::Resettable for ConfigWatchdogResetCountSpec {
    const RESET_VALUE: u32 = 0x5b9a;
}
