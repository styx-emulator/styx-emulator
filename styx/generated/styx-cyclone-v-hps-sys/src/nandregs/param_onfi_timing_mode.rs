// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_onfi_timing_mode` reader"]
pub type R = crate::R<ParamOnfiTimingModeSpec>;
#[doc = "Register `param_onfi_timing_mode` writer"]
pub type W = crate::W<ParamOnfiTimingModeSpec>;
#[doc = "Field `value` reader - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamOnfiTimingModeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Asynchronous Timing modes supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_timing_mode::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiTimingModeSpec;
impl crate::RegisterSpec for ParamOnfiTimingModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 928u64;
}
#[doc = "`read()` method returns [`param_onfi_timing_mode::R`](R) reader structure"]
impl crate::Readable for ParamOnfiTimingModeSpec {}
#[doc = "`reset()` method sets param_onfi_timing_mode to value 0"]
impl crate::Resettable for ParamOnfiTimingModeSpec {
    const RESET_VALUE: u32 = 0;
}
