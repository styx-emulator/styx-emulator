// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `status_page_cnt3` reader"]
pub type R = crate::R<StatusPageCnt3Spec>;
#[doc = "Register `status_page_cnt3` writer"]
pub type W = crate::W<StatusPageCnt3Spec>;
#[doc = "Field `value` reader - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<StatusPageCnt3Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Decrementing page count bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_page_cnt3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusPageCnt3Spec;
impl crate::RegisterSpec for StatusPageCnt3Spec {
    type Ux = u32;
    const OFFSET: u64 = 1312u64;
}
#[doc = "`read()` method returns [`status_page_cnt3::R`](R) reader structure"]
impl crate::Readable for StatusPageCnt3Spec {}
#[doc = "`reset()` method sets status_page_cnt3 to value 0"]
impl crate::Resettable for StatusPageCnt3Spec {
    const RESET_VALUE: u32 = 0;
}
