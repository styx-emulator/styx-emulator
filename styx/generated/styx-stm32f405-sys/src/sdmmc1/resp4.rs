// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RESP4` reader"]
pub type R = crate::R<Resp4Spec>;
#[doc = "Register `RESP4` writer"]
pub type W = crate::W<Resp4Spec>;
#[doc = "Field `CARDSTATUS4` reader - see Table 132"]
pub type Cardstatus4R = crate::FieldReader<u32>;
#[doc = "Field `CARDSTATUS4` writer - see Table 132"]
pub type Cardstatus4W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - see Table 132"]
    #[inline(always)]
    pub fn cardstatus4(&self) -> Cardstatus4R {
        Cardstatus4R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - see Table 132"]
    #[inline(always)]
    #[must_use]
    pub fn cardstatus4(&mut self) -> Cardstatus4W<Resp4Spec> {
        Cardstatus4W::new(self, 0)
    }
}
#[doc = "response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp4Spec;
impl crate::RegisterSpec for Resp4Spec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`resp4::R`](R) reader structure"]
impl crate::Readable for Resp4Spec {}
#[doc = "`reset()` method sets RESP4 to value 0"]
impl crate::Resettable for Resp4Spec {
    const RESET_VALUE: u32 = 0;
}
