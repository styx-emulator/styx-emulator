// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `status_err_page_addr0` reader"]
pub type R = crate::R<StatusErrPageAddr0Spec>;
#[doc = "Register `status_err_page_addr0` writer"]
pub type W = crate::W<StatusErrPageAddr0Spec>;
#[doc = "Field `value` reader - Holds the page address that resulted in a failure on program or erase operation."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Holds the page address that resulted in a failure on program or erase operation."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Holds the page address that resulted in a failure on program or erase operation."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Holds the page address that resulted in a failure on program or erase operation."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<StatusErrPageAddr0Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Erred page address bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_page_addr0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusErrPageAddr0Spec;
impl crate::RegisterSpec for StatusErrPageAddr0Spec {
    type Ux = u32;
    const OFFSET: u64 = 1088u64;
}
#[doc = "`read()` method returns [`status_err_page_addr0::R`](R) reader structure"]
impl crate::Readable for StatusErrPageAddr0Spec {}
#[doc = "`reset()` method sets status_err_page_addr0 to value 0"]
impl crate::Resettable for StatusErrPageAddr0Spec {
    const RESET_VALUE: u32 = 0;
}
