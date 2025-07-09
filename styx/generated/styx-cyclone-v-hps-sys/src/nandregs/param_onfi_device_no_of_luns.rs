// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_onfi_device_no_of_luns` reader"]
pub type R = crate::R<ParamOnfiDeviceNoOfLunsSpec>;
#[doc = "Register `param_onfi_device_no_of_luns` writer"]
pub type W = crate::W<ParamOnfiDeviceNoOfLunsSpec>;
#[doc = "Field `no_of_luns` reader - Indicates the number of LUNS present in the device"]
pub type NoOfLunsR = crate::FieldReader;
#[doc = "Field `no_of_luns` writer - Indicates the number of LUNS present in the device"]
pub type NoOfLunsW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `onfi_device` reader - Indicates if the device is an ONFI compliant device.\\[list\\]
\\[*\\]0 - Non-ONFI compliant device \\[*\\]1 - ONFI compliant device\\[/list\\]"]
pub type OnfiDeviceR = crate::BitReader;
#[doc = "Field `onfi_device` writer - Indicates if the device is an ONFI compliant device.\\[list\\]
\\[*\\]0 - Non-ONFI compliant device \\[*\\]1 - ONFI compliant device\\[/list\\]"]
pub type OnfiDeviceW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Indicates the number of LUNS present in the device"]
    #[inline(always)]
    pub fn no_of_luns(&self) -> NoOfLunsR {
        NoOfLunsR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 8 - Indicates if the device is an ONFI compliant device.\\[list\\]
\\[*\\]0 - Non-ONFI compliant device \\[*\\]1 - ONFI compliant device\\[/list\\]"]
    #[inline(always)]
    pub fn onfi_device(&self) -> OnfiDeviceR {
        OnfiDeviceR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Indicates the number of LUNS present in the device"]
    #[inline(always)]
    #[must_use]
    pub fn no_of_luns(&mut self) -> NoOfLunsW<ParamOnfiDeviceNoOfLunsSpec> {
        NoOfLunsW::new(self, 0)
    }
    #[doc = "Bit 8 - Indicates if the device is an ONFI compliant device.\\[list\\]
\\[*\\]0 - Non-ONFI compliant device \\[*\\]1 - ONFI compliant device\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn onfi_device(&mut self) -> OnfiDeviceW<ParamOnfiDeviceNoOfLunsSpec> {
        OnfiDeviceW::new(self, 8)
    }
}
#[doc = "Indicates if the device is an ONFI compliant device and the number of LUNS present in the device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_no_of_luns::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`param_onfi_device_no_of_luns::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiDeviceNoOfLunsSpec;
impl crate::RegisterSpec for ParamOnfiDeviceNoOfLunsSpec {
    type Ux = u32;
    const OFFSET: u64 = 960u64;
}
#[doc = "`read()` method returns [`param_onfi_device_no_of_luns::R`](R) reader structure"]
impl crate::Readable for ParamOnfiDeviceNoOfLunsSpec {}
#[doc = "`write(|w| ..)` method takes [`param_onfi_device_no_of_luns::W`](W) writer structure"]
impl crate::Writable for ParamOnfiDeviceNoOfLunsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets param_onfi_device_no_of_luns to value 0"]
impl crate::Resettable for ParamOnfiDeviceNoOfLunsSpec {
    const RESET_VALUE: u32 = 0;
}
