// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `JDR3` reader"]
pub type R = crate::R<Jdr3Spec>;
#[doc = "Register `JDR3` writer"]
pub type W = crate::W<Jdr3Spec>;
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
    pub fn jdata(&mut self) -> JdataW<Jdr3Spec> {
        JdataW::new(self, 0)
    }
}
#[doc = "injected data register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jdr3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Jdr3Spec;
impl crate::RegisterSpec for Jdr3Spec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`jdr3::R`](R) reader structure"]
impl crate::Readable for Jdr3Spec {}
#[doc = "`reset()` method sets JDR3 to value 0"]
impl crate::Resettable for Jdr3Spec {
    const RESET_VALUE: u32 = 0;
}
