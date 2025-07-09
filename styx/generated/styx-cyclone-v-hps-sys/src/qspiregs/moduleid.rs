// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `moduleid` reader"]
pub type R = crate::R<ModuleidSpec>;
#[doc = "Register `moduleid` writer"]
pub type W = crate::W<ModuleidSpec>;
#[doc = "Field `value` reader - "]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - "]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 25, u32>;
impl R {
    #[doc = "Bits 0:24"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits & 0x01ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:24"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ModuleidSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`moduleid::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ModuleidSpec;
impl crate::RegisterSpec for ModuleidSpec {
    type Ux = u32;
    const OFFSET: u64 = 252u64;
}
#[doc = "`read()` method returns [`moduleid::R`](R) reader structure"]
impl crate::Readable for ModuleidSpec {}
#[doc = "`reset()` method sets moduleid to value 0x1001"]
impl crate::Resettable for ModuleidSpec {
    const RESET_VALUE: u32 = 0x1001;
}
