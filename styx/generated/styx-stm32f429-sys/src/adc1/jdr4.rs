// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `JDR4` reader"]
pub type R = crate::R<Jdr4Spec>;
#[doc = "Register `JDR4` writer"]
pub type W = crate::W<Jdr4Spec>;
#[doc = "Field `JDATA` reader - Injected data"]
pub type JdataR = crate::FieldReader<u16>;
#[doc = "Field `JDATA` writer - Injected data"]
pub type JdataW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Injected data"]
    #[inline(always)]
    pub fn jdata(&self) -> JdataR {
        JdataR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Injected data"]
    #[inline(always)]
    #[must_use]
    pub fn jdata(&mut self) -> JdataW<Jdr4Spec> {
        JdataW::new(self, 0)
    }
}
#[doc = "injected data register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jdr4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Jdr4Spec;
impl crate::RegisterSpec for Jdr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`jdr4::R`](R) reader structure"]
impl crate::Readable for Jdr4Spec {}
#[doc = "`reset()` method sets JDR4 to value 0"]
impl crate::Resettable for Jdr4Spec {
    const RESET_VALUE: u32 = 0;
}
