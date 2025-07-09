// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `resp2` reader"]
pub type R = crate::R<Resp2Spec>;
#[doc = "Register `resp2` writer"]
pub type W = crate::W<Resp2Spec>;
#[doc = "Field `response2` reader - Bit\\[95:64\\]
of long response"]
pub type Response2R = crate::FieldReader<u32>;
#[doc = "Field `response2` writer - Bit\\[95:64\\]
of long response"]
pub type Response2W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Bit\\[95:64\\]
of long response"]
    #[inline(always)]
    pub fn response2(&self) -> Response2R {
        Response2R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Bit\\[95:64\\]
of long response"]
    #[inline(always)]
    #[must_use]
    pub fn response2(&mut self) -> Response2W<Resp2Spec> {
        Response2W::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp2Spec;
impl crate::RegisterSpec for Resp2Spec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`resp2::R`](R) reader structure"]
impl crate::Readable for Resp2Spec {}
#[doc = "`reset()` method sets resp2 to value 0"]
impl crate::Resettable for Resp2Spec {
    const RESET_VALUE: u32 = 0;
}
