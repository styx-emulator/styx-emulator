// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_global_int_enable` reader"]
pub type R = crate::R<ConfigGlobalIntEnableSpec>;
#[doc = "Register `config_global_int_enable` writer"]
pub type W = crate::W<ConfigGlobalIntEnableSpec>;
#[doc = "Field `flag` reader - Host will receive an interrupt only when this bit is set."]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - Host will receive an interrupt only when this bit is set."]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `timeout_disable` reader - Watchdog timer logic will be de-activated when this bit is set."]
pub type TimeoutDisableR = crate::BitReader;
#[doc = "Field `timeout_disable` writer - Watchdog timer logic will be de-activated when this bit is set."]
pub type TimeoutDisableW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `error_rpt_disable` reader - Command and ECC uncorrectable failures will not be reported when this bit is set"]
pub type ErrorRptDisableR = crate::BitReader;
#[doc = "Field `error_rpt_disable` writer - Command and ECC uncorrectable failures will not be reported when this bit is set"]
pub type ErrorRptDisableW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Host will receive an interrupt only when this bit is set."]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 4 - Watchdog timer logic will be de-activated when this bit is set."]
    #[inline(always)]
    pub fn timeout_disable(&self) -> TimeoutDisableR {
        TimeoutDisableR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 8 - Command and ECC uncorrectable failures will not be reported when this bit is set"]
    #[inline(always)]
    pub fn error_rpt_disable(&self) -> ErrorRptDisableR {
        ErrorRptDisableR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Host will receive an interrupt only when this bit is set."]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigGlobalIntEnableSpec> {
        FlagW::new(self, 0)
    }
    #[doc = "Bit 4 - Watchdog timer logic will be de-activated when this bit is set."]
    #[inline(always)]
    #[must_use]
    pub fn timeout_disable(&mut self) -> TimeoutDisableW<ConfigGlobalIntEnableSpec> {
        TimeoutDisableW::new(self, 4)
    }
    #[doc = "Bit 8 - Command and ECC uncorrectable failures will not be reported when this bit is set"]
    #[inline(always)]
    #[must_use]
    pub fn error_rpt_disable(&mut self) -> ErrorRptDisableW<ConfigGlobalIntEnableSpec> {
        ErrorRptDisableW::new(self, 8)
    }
}
#[doc = "Global Interrupt enable and Error/Timeout disable.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_global_int_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_global_int_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigGlobalIntEnableSpec;
impl crate::RegisterSpec for ConfigGlobalIntEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 240u64;
}
#[doc = "`read()` method returns [`config_global_int_enable::R`](R) reader structure"]
impl crate::Readable for ConfigGlobalIntEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`config_global_int_enable::W`](W) writer structure"]
impl crate::Writable for ConfigGlobalIntEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_global_int_enable to value 0"]
impl crate::Resettable for ConfigGlobalIntEnableSpec {
    const RESET_VALUE: u32 = 0;
}
