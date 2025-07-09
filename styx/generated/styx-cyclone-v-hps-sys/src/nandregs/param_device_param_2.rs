// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_device_param_2` reader"]
pub type R = crate::R<ParamDeviceParam2Spec>;
#[doc = "Register `param_device_param_2` writer"]
pub type W = crate::W<ParamDeviceParam2Spec>;
#[doc = "Field `value` reader - Reserved."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Reserved."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Reserved."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Reserved."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamDeviceParam2Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_param_2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamDeviceParam2Spec;
impl crate::RegisterSpec for ParamDeviceParam2Spec {
    type Ux = u32;
    const OFFSET: u64 = 832u64;
}
#[doc = "`read()` method returns [`param_device_param_2::R`](R) reader structure"]
impl crate::Readable for ParamDeviceParam2Spec {}
#[doc = "`reset()` method sets param_device_param_2 to value 0"]
impl crate::Resettable for ParamDeviceParam2Spec {
    const RESET_VALUE: u32 = 0;
}
