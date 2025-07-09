// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctr` reader"]
pub type R = crate::R<CtrSpec>;
#[doc = "Register `ctr` writer"]
pub type W = crate::W<CtrSpec>;
#[doc = "Field `peripheral_id` reader - This register contains the peripherals identification code."]
pub type PeripheralIdR = crate::FieldReader<u32>;
#[doc = "Field `peripheral_id` writer - This register contains the peripherals identification code."]
pub type PeripheralIdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This register contains the peripherals identification code."]
    #[inline(always)]
    pub fn peripheral_id(&self) -> PeripheralIdR {
        PeripheralIdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This register contains the peripherals identification code."]
    #[inline(always)]
    #[must_use]
    pub fn peripheral_id(&mut self) -> PeripheralIdW<CtrSpec> {
        PeripheralIdW::new(self, 0)
    }
}
#[doc = "Describes a hex value associated with the component.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrSpec;
impl crate::RegisterSpec for CtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 252u64;
}
#[doc = "`read()` method returns [`ctr::R`](R) reader structure"]
impl crate::Readable for CtrSpec {}
#[doc = "`reset()` method sets ctr to value 0x4457_0110"]
impl crate::Resettable for CtrSpec {
    const RESET_VALUE: u32 = 0x4457_0110;
}
