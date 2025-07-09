// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PECR` reader"]
pub type R = crate::R<PecrSpec>;
#[doc = "Register `PECR` writer"]
pub type W = crate::W<PecrSpec>;
#[doc = "Field `PEC` reader - Packet error checking register"]
pub type PecR = crate::FieldReader;
#[doc = "Field `PEC` writer - Packet error checking register"]
pub type PecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Packet error checking register"]
    #[inline(always)]
    pub fn pec(&self) -> PecR {
        PecR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Packet error checking register"]
    #[inline(always)]
    #[must_use]
    pub fn pec(&mut self) -> PecW<PecrSpec> {
        PecW::new(self, 0)
    }
}
#[doc = "PEC register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pecr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PecrSpec;
impl crate::RegisterSpec for PecrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`pecr::R`](R) reader structure"]
impl crate::Readable for PecrSpec {}
#[doc = "`reset()` method sets PECR to value 0"]
impl crate::Resettable for PecrSpec {
    const RESET_VALUE: u32 = 0;
}
