// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ucv` reader"]
pub type R = crate::R<UcvSpec>;
#[doc = "Register `ucv` writer"]
pub type W = crate::W<UcvSpec>;
#[doc = "Field `uart_component_version` reader - ASCII value for each number in the version, followed by *For example 32_30_31_2A represents the version 2.01a"]
pub type UartComponentVersionR = crate::FieldReader<u32>;
#[doc = "Field `uart_component_version` writer - ASCII value for each number in the version, followed by *For example 32_30_31_2A represents the version 2.01a"]
pub type UartComponentVersionW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - ASCII value for each number in the version, followed by *For example 32_30_31_2A represents the version 2.01a"]
    #[inline(always)]
    pub fn uart_component_version(&self) -> UartComponentVersionR {
        UartComponentVersionR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - ASCII value for each number in the version, followed by *For example 32_30_31_2A represents the version 2.01a"]
    #[inline(always)]
    #[must_use]
    pub fn uart_component_version(&mut self) -> UartComponentVersionW<UcvSpec> {
        UartComponentVersionW::new(self, 0)
    }
}
#[doc = "Used only with Additional Features\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ucv::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct UcvSpec;
impl crate::RegisterSpec for UcvSpec {
    type Ux = u32;
    const OFFSET: u64 = 248u64;
}
#[doc = "`read()` method returns [`ucv::R`](R) reader structure"]
impl crate::Readable for UcvSpec {}
#[doc = "`reset()` method sets ucv to value 0x3331_312a"]
impl crate::Resettable for UcvSpec {
    const RESET_VALUE: u32 = 0x3331_312a;
}
