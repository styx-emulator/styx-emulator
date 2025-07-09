// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `resp1` reader"]
pub type R = crate::R<Resp1Spec>;
#[doc = "Register `resp1` writer"]
pub type W = crate::W<Resp1Spec>;
#[doc = "Field `response1` reader - Register represents bit\\[63:32\\]
of long response. When CIU sends auto-stop command, then response is saved in register. Response for previous command sent by host is still preserved in Response 0 register. Additional auto-stop issued only for data transfer commands, and response type is always short for them."]
pub type Response1R = crate::FieldReader<u32>;
#[doc = "Field `response1` writer - Register represents bit\\[63:32\\]
of long response. When CIU sends auto-stop command, then response is saved in register. Response for previous command sent by host is still preserved in Response 0 register. Additional auto-stop issued only for data transfer commands, and response type is always short for them."]
pub type Response1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Register represents bit\\[63:32\\]
of long response. When CIU sends auto-stop command, then response is saved in register. Response for previous command sent by host is still preserved in Response 0 register. Additional auto-stop issued only for data transfer commands, and response type is always short for them."]
    #[inline(always)]
    pub fn response1(&self) -> Response1R {
        Response1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Register represents bit\\[63:32\\]
of long response. When CIU sends auto-stop command, then response is saved in register. Response for previous command sent by host is still preserved in Response 0 register. Additional auto-stop issued only for data transfer commands, and response type is always short for them."]
    #[inline(always)]
    #[must_use]
    pub fn response1(&mut self) -> Response1W<Resp1Spec> {
        Response1W::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp1Spec;
impl crate::RegisterSpec for Resp1Spec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`resp1::R`](R) reader structure"]
impl crate::Readable for Resp1Spec {}
#[doc = "`reset()` method sets resp1 to value 0"]
impl crate::Resettable for Resp1Spec {
    const RESET_VALUE: u32 = 0;
}
