// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_comp_type` reader"]
pub type R = crate::R<IcCompTypeSpec>;
#[doc = "Register `ic_comp_type` writer"]
pub type W = crate::W<IcCompTypeSpec>;
#[doc = "Field `ic_comp_type` reader - Designware Component Type number = 0x44_57_01_40. This assigned unique hex value is constant and is derived from the two ASCII letters 'DW' followed by a 16-bit unsigned number."]
pub type IcCompTypeR = crate::FieldReader<u32>;
#[doc = "Field `ic_comp_type` writer - Designware Component Type number = 0x44_57_01_40. This assigned unique hex value is constant and is derived from the two ASCII letters 'DW' followed by a 16-bit unsigned number."]
pub type IcCompTypeW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Designware Component Type number = 0x44_57_01_40. This assigned unique hex value is constant and is derived from the two ASCII letters 'DW' followed by a 16-bit unsigned number."]
    #[inline(always)]
    pub fn ic_comp_type(&self) -> IcCompTypeR {
        IcCompTypeR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Designware Component Type number = 0x44_57_01_40. This assigned unique hex value is constant and is derived from the two ASCII letters 'DW' followed by a 16-bit unsigned number."]
    #[inline(always)]
    #[must_use]
    pub fn ic_comp_type(&mut self) -> IcCompTypeW<IcCompTypeSpec> {
        IcCompTypeW::new(self, 0)
    }
}
#[doc = "Describes a unique ASCII value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_comp_type::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcCompTypeSpec;
impl crate::RegisterSpec for IcCompTypeSpec {
    type Ux = u32;
    const OFFSET: u64 = 252u64;
}
#[doc = "`read()` method returns [`ic_comp_type::R`](R) reader structure"]
impl crate::Readable for IcCompTypeSpec {}
#[doc = "`reset()` method sets ic_comp_type to value 0x4457_0140"]
impl crate::Resettable for IcCompTypeSpec {
    const RESET_VALUE: u32 = 0x4457_0140;
}
