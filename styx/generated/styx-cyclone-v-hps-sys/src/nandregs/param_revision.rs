// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_revision` reader"]
pub type R = crate::R<ParamRevisionSpec>;
#[doc = "Register `param_revision` writer"]
pub type W = crate::W<ParamRevisionSpec>;
#[doc = "Field `value` reader - Controller revision number"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Controller revision number"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Controller revision number"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Controller revision number"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamRevisionSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Controller revision number\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_revision::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamRevisionSpec;
impl crate::RegisterSpec for ParamRevisionSpec {
    type Ux = u32;
    const OFFSET: u64 = 880u64;
}
#[doc = "`read()` method returns [`param_revision::R`](R) reader structure"]
impl crate::Readable for ParamRevisionSpec {}
#[doc = "`reset()` method sets param_revision to value 0x05"]
impl crate::Resettable for ParamRevisionSpec {
    const RESET_VALUE: u32 = 0x05;
}
