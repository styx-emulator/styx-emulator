// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RESP1` reader"]
pub type R = crate::R<Resp1Spec>;
#[doc = "Register `RESP1` writer"]
pub type W = crate::W<Resp1Spec>;
#[doc = "Field `CARDSTATUS1` reader - see Table 132."]
pub type Cardstatus1R = crate::FieldReader<u32>;
#[doc = "Field `CARDSTATUS1` writer - see Table 132."]
pub type Cardstatus1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - see Table 132."]
    #[inline(always)]
    pub fn cardstatus1(&self) -> Cardstatus1R {
        Cardstatus1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - see Table 132."]
    #[inline(always)]
    #[must_use]
    pub fn cardstatus1(&mut self) -> Cardstatus1W<Resp1Spec> {
        Cardstatus1W::new(self, 0)
    }
}
#[doc = "response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp1Spec;
impl crate::RegisterSpec for Resp1Spec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`resp1::R`](R) reader structure"]
impl crate::Readable for Resp1Spec {}
#[doc = "`reset()` method sets RESP1 to value 0"]
impl crate::Resettable for Resp1Spec {
    const RESET_VALUE: u32 = 0;
}
