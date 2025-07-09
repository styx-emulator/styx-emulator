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
#[doc = "Register `param_onfi_device_no_of_blocks_per_lun_u` reader"]
pub type R = crate::R<ParamOnfiDeviceNoOfBlocksPerLunUSpec>;
#[doc = "Register `param_onfi_device_no_of_blocks_per_lun_u` writer"]
pub type W = crate::W<ParamOnfiDeviceNoOfBlocksPerLunUSpec>;
#[doc = "Field `value` reader - Indicates the upper bits of number of blocks per LUN present in the ONFI complaint device."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Indicates the upper bits of number of blocks per LUN present in the ONFI complaint device."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Indicates the upper bits of number of blocks per LUN present in the ONFI complaint device."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Indicates the upper bits of number of blocks per LUN present in the ONFI complaint device."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamOnfiDeviceNoOfBlocksPerLunUSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Upper bits of number of blocks per LUN present in the ONFI complaint device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_no_of_blocks_per_lun_u::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiDeviceNoOfBlocksPerLunUSpec;
impl crate::RegisterSpec for ParamOnfiDeviceNoOfBlocksPerLunUSpec {
    type Ux = u32;
    const OFFSET: u64 = 992u64;
}
#[doc = "`read()` method returns [`param_onfi_device_no_of_blocks_per_lun_u::R`](R) reader structure"]
impl crate::Readable for ParamOnfiDeviceNoOfBlocksPerLunUSpec {}
#[doc = "`reset()` method sets param_onfi_device_no_of_blocks_per_lun_u to value 0"]
impl crate::Resettable for ParamOnfiDeviceNoOfBlocksPerLunUSpec {
    const RESET_VALUE: u32 = 0;
}
