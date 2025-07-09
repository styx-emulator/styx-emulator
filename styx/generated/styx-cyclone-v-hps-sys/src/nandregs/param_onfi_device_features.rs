// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_onfi_device_features` reader"]
pub type R = crate::R<ParamOnfiDeviceFeaturesSpec>;
#[doc = "Register `param_onfi_device_features` writer"]
pub type W = crate::W<ParamOnfiDeviceFeaturesSpec>;
#[doc = "Field `value` reader - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports 16 bit data bus width. \\[*\\]Bit 1 - Supports multiple LUN operations. \\[*\\]Bit 2 - Supports non-sequential page programming. \\[*\\]Bit 3 - Supports interleaved program and erase operations. \\[*\\]Bit 4 - Supports odd to even page copyback. \\[*\\]Bit 5 - Supports source synchronous. \\[*\\]Bit 6 - Supports interleaved read operations. \\[*\\]Bit 7 - Supports extended parameter page. \\[*\\]Bit 8 - Supports program page register clear enhancement. \\[*\\]Bit 9-15 - Reserved.\\[/list\\]"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports 16 bit data bus width. \\[*\\]Bit 1 - Supports multiple LUN operations. \\[*\\]Bit 2 - Supports non-sequential page programming. \\[*\\]Bit 3 - Supports interleaved program and erase operations. \\[*\\]Bit 4 - Supports odd to even page copyback. \\[*\\]Bit 5 - Supports source synchronous. \\[*\\]Bit 6 - Supports interleaved read operations. \\[*\\]Bit 7 - Supports extended parameter page. \\[*\\]Bit 8 - Supports program page register clear enhancement. \\[*\\]Bit 9-15 - Reserved.\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports 16 bit data bus width. \\[*\\]Bit 1 - Supports multiple LUN operations. \\[*\\]Bit 2 - Supports non-sequential page programming. \\[*\\]Bit 3 - Supports interleaved program and erase operations. \\[*\\]Bit 4 - Supports odd to even page copyback. \\[*\\]Bit 5 - Supports source synchronous. \\[*\\]Bit 6 - Supports interleaved read operations. \\[*\\]Bit 7 - Supports extended parameter page. \\[*\\]Bit 8 - Supports program page register clear enhancement. \\[*\\]Bit 9-15 - Reserved.\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports 16 bit data bus width. \\[*\\]Bit 1 - Supports multiple LUN operations. \\[*\\]Bit 2 - Supports non-sequential page programming. \\[*\\]Bit 3 - Supports interleaved program and erase operations. \\[*\\]Bit 4 - Supports odd to even page copyback. \\[*\\]Bit 5 - Supports source synchronous. \\[*\\]Bit 6 - Supports interleaved read operations. \\[*\\]Bit 7 - Supports extended parameter page. \\[*\\]Bit 8 - Supports program page register clear enhancement. \\[*\\]Bit 9-15 - Reserved.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamOnfiDeviceFeaturesSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Features supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_features::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiDeviceFeaturesSpec;
impl crate::RegisterSpec for ParamOnfiDeviceFeaturesSpec {
    type Ux = u32;
    const OFFSET: u64 = 896u64;
}
#[doc = "`read()` method returns [`param_onfi_device_features::R`](R) reader structure"]
impl crate::Readable for ParamOnfiDeviceFeaturesSpec {}
#[doc = "`reset()` method sets param_onfi_device_features to value 0"]
impl crate::Resettable for ParamOnfiDeviceFeaturesSpec {
    const RESET_VALUE: u32 = 0;
}
