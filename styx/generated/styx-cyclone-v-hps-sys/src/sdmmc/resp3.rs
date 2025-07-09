// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `resp3` reader"]
pub type R = crate::R<Resp3Spec>;
#[doc = "Register `resp3` writer"]
pub type W = crate::W<Resp3Spec>;
#[doc = "Field `response3` reader - Bit\\[127:96\\]
of long response"]
pub type Response3R = crate::FieldReader<u32>;
#[doc = "Field `response3` writer - Bit\\[127:96\\]
of long response"]
pub type Response3W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Bit\\[127:96\\]
of long response"]
    #[inline(always)]
    pub fn response3(&self) -> Response3R {
        Response3R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Bit\\[127:96\\]
of long response"]
    #[inline(always)]
    #[must_use]
    pub fn response3(&mut self) -> Response3W<Resp3Spec> {
        Response3W::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp3Spec;
impl crate::RegisterSpec for Resp3Spec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`resp3::R`](R) reader structure"]
impl crate::Readable for Resp3Spec {}
#[doc = "`reset()` method sets resp3 to value 0"]
impl crate::Resettable for Resp3Spec {
    const RESET_VALUE: u32 = 0;
}
