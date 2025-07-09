// SPDX-License-Identifier: BSD-2-Clause
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
