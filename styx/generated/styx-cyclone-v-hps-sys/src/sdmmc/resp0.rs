// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `resp0` reader"]
pub type R = crate::R<Resp0Spec>;
#[doc = "Register `resp0` writer"]
pub type W = crate::W<Resp0Spec>;
#[doc = "Field `response0` reader - Bit\\[31:0\\]
of response."]
pub type Response0R = crate::FieldReader<u32>;
#[doc = "Field `response0` writer - Bit\\[31:0\\]
of response."]
pub type Response0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Bit\\[31:0\\]
of response."]
    #[inline(always)]
    pub fn response0(&self) -> Response0R {
        Response0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Bit\\[31:0\\]
of response."]
    #[inline(always)]
    #[must_use]
    pub fn response0(&mut self) -> Response0W<Resp0Spec> {
        Response0W::new(self, 0)
    }
}
#[doc = "Preserves previous command.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp0Spec;
impl crate::RegisterSpec for Resp0Spec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`resp0::R`](R) reader structure"]
impl crate::Readable for Resp0Spec {}
#[doc = "`reset()` method sets resp0 to value 0"]
impl crate::Resettable for Resp0Spec {
    const RESET_VALUE: u32 = 0;
}
