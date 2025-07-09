// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
