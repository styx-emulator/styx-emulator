// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_comp_version` reader"]
pub type R = crate::R<WdtCompVersionSpec>;
#[doc = "Register `wdt_comp_version` writer"]
pub type W = crate::W<WdtCompVersionSpec>;
#[doc = "Field `wdt_comp_version` reader - ASCII value for each number in the version, followed by *. For example, 32_30_31_2A represents the version 2.01*."]
pub type WdtCompVersionR = crate::FieldReader<u32>;
#[doc = "Field `wdt_comp_version` writer - ASCII value for each number in the version, followed by *. For example, 32_30_31_2A represents the version 2.01*."]
pub type WdtCompVersionW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - ASCII value for each number in the version, followed by *. For example, 32_30_31_2A represents the version 2.01*."]
    #[inline(always)]
    pub fn wdt_comp_version(&self) -> WdtCompVersionR {
        WdtCompVersionR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - ASCII value for each number in the version, followed by *. For example, 32_30_31_2A represents the version 2.01*."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_comp_version(&mut self) -> WdtCompVersionW<WdtCompVersionSpec> {
        WdtCompVersionW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_comp_version::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCompVersionSpec;
impl crate::RegisterSpec for WdtCompVersionSpec {
    type Ux = u32;
    const OFFSET: u64 = 248u64;
}
#[doc = "`read()` method returns [`wdt_comp_version::R`](R) reader structure"]
impl crate::Readable for WdtCompVersionSpec {}
#[doc = "`reset()` method sets wdt_comp_version to value 0x3130_362a"]
impl crate::Resettable for WdtCompVersionSpec {
    const RESET_VALUE: u32 = 0x3130_362a;
}
