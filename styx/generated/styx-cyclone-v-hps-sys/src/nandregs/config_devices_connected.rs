// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_devices_connected` reader"]
pub type R = crate::R<ConfigDevicesConnectedSpec>;
#[doc = "Register `config_devices_connected` writer"]
pub type W = crate::W<ConfigDevicesConnectedSpec>;
#[doc = "Field `value` reader - Indicates the number of devices connected to a bank. At reset, the value loaded is the maximum possible devices that could be connected in this configuration."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Indicates the number of devices connected to a bank. At reset, the value loaded is the maximum possible devices that could be connected in this configuration."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:2 - Indicates the number of devices connected to a bank. At reset, the value loaded is the maximum possible devices that could be connected in this configuration."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - Indicates the number of devices connected to a bank. At reset, the value loaded is the maximum possible devices that could be connected in this configuration."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigDevicesConnectedSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Number of Devices connected on one bank\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_devices_connected::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_devices_connected::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigDevicesConnectedSpec;
impl crate::RegisterSpec for ConfigDevicesConnectedSpec {
    type Ux = u32;
    const OFFSET: u64 = 592u64;
}
#[doc = "`read()` method returns [`config_devices_connected::R`](R) reader structure"]
impl crate::Readable for ConfigDevicesConnectedSpec {}
#[doc = "`write(|w| ..)` method takes [`config_devices_connected::W`](W) writer structure"]
impl crate::Writable for ConfigDevicesConnectedSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_devices_connected to value 0"]
impl crate::Resettable for ConfigDevicesConnectedSpec {
    const RESET_VALUE: u32 = 0;
}
