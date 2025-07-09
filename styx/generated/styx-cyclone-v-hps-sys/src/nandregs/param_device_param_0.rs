// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_device_param_0` reader"]
pub type R = crate::R<ParamDeviceParam0Spec>;
#[doc = "Register `param_device_param_0` writer"]
pub type W = crate::W<ParamDeviceParam0Spec>;
#[doc = "Field `value` reader - 3rd byte relating to Device Signature. This register is updated only for Legacy NAND devices."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - 3rd byte relating to Device Signature. This register is updated only for Legacy NAND devices."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - 3rd byte relating to Device Signature. This register is updated only for Legacy NAND devices."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - 3rd byte relating to Device Signature. This register is updated only for Legacy NAND devices."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamDeviceParam0Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_param_0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamDeviceParam0Spec;
impl crate::RegisterSpec for ParamDeviceParam0Spec {
    type Ux = u32;
    const OFFSET: u64 = 800u64;
}
#[doc = "`read()` method returns [`param_device_param_0::R`](R) reader structure"]
impl crate::Readable for ParamDeviceParam0Spec {}
#[doc = "`reset()` method sets param_device_param_0 to value 0"]
impl crate::Resettable for ParamDeviceParam0Spec {
    const RESET_VALUE: u32 = 0;
}
