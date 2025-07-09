// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ECCR2` reader"]
pub type R = crate::R<Eccr2Spec>;
#[doc = "Register `ECCR2` writer"]
pub type W = crate::W<Eccr2Spec>;
#[doc = "Field `ECCx` reader - ECCx"]
pub type EccxR = crate::FieldReader<u32>;
#[doc = "Field `ECCx` writer - ECCx"]
pub type EccxW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - ECCx"]
    #[inline(always)]
    pub fn eccx(&self) -> EccxR {
        EccxR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - ECCx"]
    #[inline(always)]
    #[must_use]
    pub fn eccx(&mut self) -> EccxW<Eccr2Spec> {
        EccxW::new(self, 0)
    }
}
#[doc = "ECC result register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccr2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Eccr2Spec;
impl crate::RegisterSpec for Eccr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 116u64;
}
#[doc = "`read()` method returns [`eccr2::R`](R) reader structure"]
impl crate::Readable for Eccr2Spec {}
#[doc = "`reset()` method sets ECCR2 to value 0"]
impl crate::Resettable for Eccr2Spec {
    const RESET_VALUE: u32 = 0;
}
