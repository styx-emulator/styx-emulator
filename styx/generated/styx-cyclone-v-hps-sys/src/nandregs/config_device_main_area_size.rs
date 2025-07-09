// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_device_main_area_size` reader"]
pub type R = crate::R<ConfigDeviceMainAreaSizeSpec>;
#[doc = "Register `config_device_main_area_size` writer"]
pub type W = crate::W<ConfigDeviceMainAreaSizeSpec>;
#[doc = "Field `value` reader - Controller will read Electronic Signature of devices and populate this field. The PAGE512 field of the System Manager NANDGRP_BOOTSTRAP register will determine the value of this field to be 512. Software could also choose to override the populated value."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Controller will read Electronic Signature of devices and populate this field. The PAGE512 field of the System Manager NANDGRP_BOOTSTRAP register will determine the value of this field to be 512. Software could also choose to override the populated value."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Controller will read Electronic Signature of devices and populate this field. The PAGE512 field of the System Manager NANDGRP_BOOTSTRAP register will determine the value of this field to be 512. Software could also choose to override the populated value."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Controller will read Electronic Signature of devices and populate this field. The PAGE512 field of the System Manager NANDGRP_BOOTSTRAP register will determine the value of this field to be 512. Software could also choose to override the populated value."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigDeviceMainAreaSizeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Page main area size of device in bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_main_area_size::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_main_area_size::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigDeviceMainAreaSizeSpec;
impl crate::RegisterSpec for ConfigDeviceMainAreaSizeSpec {
    type Ux = u32;
    const OFFSET: u64 = 368u64;
}
#[doc = "`read()` method returns [`config_device_main_area_size::R`](R) reader structure"]
impl crate::Readable for ConfigDeviceMainAreaSizeSpec {}
#[doc = "`write(|w| ..)` method takes [`config_device_main_area_size::W`](W) writer structure"]
impl crate::Writable for ConfigDeviceMainAreaSizeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_device_main_area_size to value 0"]
impl crate::Resettable for ConfigDeviceMainAreaSizeSpec {
    const RESET_VALUE: u32 = 0;
}
