// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RESP2` reader"]
pub type R = crate::R<Resp2Spec>;
#[doc = "Register `RESP2` writer"]
pub type W = crate::W<Resp2Spec>;
#[doc = "Field `CARDSTATUS2` reader - see Table 132."]
pub type Cardstatus2R = crate::FieldReader<u32>;
#[doc = "Field `CARDSTATUS2` writer - see Table 132."]
pub type Cardstatus2W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - see Table 132."]
    #[inline(always)]
    pub fn cardstatus2(&self) -> Cardstatus2R {
        Cardstatus2R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - see Table 132."]
    #[inline(always)]
    #[must_use]
    pub fn cardstatus2(&mut self) -> Cardstatus2W<Resp2Spec> {
        Cardstatus2W::new(self, 0)
    }
}
#[doc = "response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp2Spec;
impl crate::RegisterSpec for Resp2Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`resp2::R`](R) reader structure"]
impl crate::Readable for Resp2Spec {}
#[doc = "`reset()` method sets RESP2 to value 0"]
impl crate::Resettable for Resp2Spec {
    const RESET_VALUE: u32 = 0;
}
