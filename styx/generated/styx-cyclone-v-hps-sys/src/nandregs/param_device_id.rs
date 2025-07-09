// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_device_id` reader"]
pub type R = crate::R<ParamDeviceIdSpec>;
#[doc = "Register `param_device_id` writer"]
pub type W = crate::W<ParamDeviceIdSpec>;
#[doc = "Field `value` reader - Device ID. This register is updated only for Legacy NAND devices."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Device ID. This register is updated only for Legacy NAND devices."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Device ID. This register is updated only for Legacy NAND devices."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Device ID. This register is updated only for Legacy NAND devices."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamDeviceIdSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_id::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamDeviceIdSpec;
impl crate::RegisterSpec for ParamDeviceIdSpec {
    type Ux = u32;
    const OFFSET: u64 = 784u64;
}
#[doc = "`read()` method returns [`param_device_id::R`](R) reader structure"]
impl crate::Readable for ParamDeviceIdSpec {}
#[doc = "`reset()` method sets param_device_id to value 0"]
impl crate::Resettable for ParamDeviceIdSpec {
    const RESET_VALUE: u32 = 0;
}
