// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_onfi_device_no_of_blocks_per_lun_l` reader"]
pub type R = crate::R<ParamOnfiDeviceNoOfBlocksPerLunLSpec>;
#[doc = "Register `param_onfi_device_no_of_blocks_per_lun_l` writer"]
pub type W = crate::W<ParamOnfiDeviceNoOfBlocksPerLunLSpec>;
#[doc = "Field `value` reader - Indicates the lower bits of number of blocks per LUN present in the ONFI complaint device."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Indicates the lower bits of number of blocks per LUN present in the ONFI complaint device."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Indicates the lower bits of number of blocks per LUN present in the ONFI complaint device."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Indicates the lower bits of number of blocks per LUN present in the ONFI complaint device."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamOnfiDeviceNoOfBlocksPerLunLSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Lower bits of number of blocks per LUN present in the ONFI complaint device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_no_of_blocks_per_lun_l::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiDeviceNoOfBlocksPerLunLSpec;
impl crate::RegisterSpec for ParamOnfiDeviceNoOfBlocksPerLunLSpec {
    type Ux = u32;
    const OFFSET: u64 = 976u64;
}
#[doc = "`read()` method returns [`param_onfi_device_no_of_blocks_per_lun_l::R`](R) reader structure"]
impl crate::Readable for ParamOnfiDeviceNoOfBlocksPerLunLSpec {}
#[doc = "`reset()` method sets param_onfi_device_no_of_blocks_per_lun_l to value 0"]
impl crate::Resettable for ParamOnfiDeviceNoOfBlocksPerLunLSpec {
    const RESET_VALUE: u32 = 0;
}
