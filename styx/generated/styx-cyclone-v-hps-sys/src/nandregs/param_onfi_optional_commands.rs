// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_onfi_optional_commands` reader"]
pub type R = crate::R<ParamOnfiOptionalCommandsSpec>;
#[doc = "Register `param_onfi_optional_commands` writer"]
pub type W = crate::W<ParamOnfiOptionalCommandsSpec>;
#[doc = "Field `value` reader - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports page cache program command. \\[*\\]Bit 1 - Supports read cache commands. \\[*\\]Bit 2 - Supports get and set features. \\[*\\]Bit 3 - Supports read status enhanced commands. \\[*\\]Bit 4 - Supports copyback. \\[*\\]Bit 5 - Supports Read Unique Id. \\[*\\]Bit 6 - Supports Change Read Column Enhanced. \\[*\\]Bit 7 - Supports change row address. \\[*\\]Bit 8 - Supports Change small data move. \\[*\\]Bit 9 - Supports RESET Lun. \\[*\\]Bit 10-15 - Reserved.\\[/list\\]"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports page cache program command. \\[*\\]Bit 1 - Supports read cache commands. \\[*\\]Bit 2 - Supports get and set features. \\[*\\]Bit 3 - Supports read status enhanced commands. \\[*\\]Bit 4 - Supports copyback. \\[*\\]Bit 5 - Supports Read Unique Id. \\[*\\]Bit 6 - Supports Change Read Column Enhanced. \\[*\\]Bit 7 - Supports change row address. \\[*\\]Bit 8 - Supports Change small data move. \\[*\\]Bit 9 - Supports RESET Lun. \\[*\\]Bit 10-15 - Reserved.\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports page cache program command. \\[*\\]Bit 1 - Supports read cache commands. \\[*\\]Bit 2 - Supports get and set features. \\[*\\]Bit 3 - Supports read status enhanced commands. \\[*\\]Bit 4 - Supports copyback. \\[*\\]Bit 5 - Supports Read Unique Id. \\[*\\]Bit 6 - Supports Change Read Column Enhanced. \\[*\\]Bit 7 - Supports change row address. \\[*\\]Bit 8 - Supports Change small data move. \\[*\\]Bit 9 - Supports RESET Lun. \\[*\\]Bit 10-15 - Reserved.\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports page cache program command. \\[*\\]Bit 1 - Supports read cache commands. \\[*\\]Bit 2 - Supports get and set features. \\[*\\]Bit 3 - Supports read status enhanced commands. \\[*\\]Bit 4 - Supports copyback. \\[*\\]Bit 5 - Supports Read Unique Id. \\[*\\]Bit 6 - Supports Change Read Column Enhanced. \\[*\\]Bit 7 - Supports change row address. \\[*\\]Bit 8 - Supports Change small data move. \\[*\\]Bit 9 - Supports RESET Lun. \\[*\\]Bit 10-15 - Reserved.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamOnfiOptionalCommandsSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Optional commands supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_optional_commands::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiOptionalCommandsSpec;
impl crate::RegisterSpec for ParamOnfiOptionalCommandsSpec {
    type Ux = u32;
    const OFFSET: u64 = 912u64;
}
#[doc = "`read()` method returns [`param_onfi_optional_commands::R`](R) reader structure"]
impl crate::Readable for ParamOnfiOptionalCommandsSpec {}
#[doc = "`reset()` method sets param_onfi_optional_commands to value 0"]
impl crate::Resettable for ParamOnfiOptionalCommandsSpec {
    const RESET_VALUE: u32 = 0;
}
