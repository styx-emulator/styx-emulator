// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DR` reader"]
pub type R = crate::R<DrSpec>;
#[doc = "Register `DR` writer"]
pub type W = crate::W<DrSpec>;
#[doc = "Field `RNDATA` reader - Random data"]
pub type RndataR = crate::FieldReader<u32>;
#[doc = "Field `RNDATA` writer - Random data"]
pub type RndataW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Random data"]
    #[inline(always)]
    pub fn rndata(&self) -> RndataR {
        RndataR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Random data"]
    #[inline(always)]
    #[must_use]
    pub fn rndata(&mut self) -> RndataW<DrSpec> {
        RndataW::new(self, 0)
    }
}
#[doc = "data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DrSpec;
impl crate::RegisterSpec for DrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`dr::R`](R) reader structure"]
impl crate::Readable for DrSpec {}
#[doc = "`reset()` method sets DR to value 0"]
impl crate::Resettable for DrSpec {
    const RESET_VALUE: u32 = 0;
}
