// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_ccvr` reader"]
pub type R = crate::R<WdtCcvrSpec>;
#[doc = "Register `wdt_ccvr` writer"]
pub type W = crate::W<WdtCcvrSpec>;
#[doc = "Field `wdt_ccvr` reader - This register provides the current value of the internal counter."]
pub type WdtCcvrR = crate::FieldReader<u32>;
#[doc = "Field `wdt_ccvr` writer - This register provides the current value of the internal counter."]
pub type WdtCcvrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This register provides the current value of the internal counter."]
    #[inline(always)]
    pub fn wdt_ccvr(&self) -> WdtCcvrR {
        WdtCcvrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This register provides the current value of the internal counter."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_ccvr(&mut self) -> WdtCcvrW<WdtCcvrSpec> {
        WdtCcvrW::new(self, 0)
    }
}
#[doc = "See Field Description\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_ccvr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCcvrSpec;
impl crate::RegisterSpec for WdtCcvrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`wdt_ccvr::R`](R) reader structure"]
impl crate::Readable for WdtCcvrSpec {}
#[doc = "`reset()` method sets wdt_ccvr to value 0x7fff_ffff"]
impl crate::Resettable for WdtCcvrSpec {
    const RESET_VALUE: u32 = 0x7fff_ffff;
}
