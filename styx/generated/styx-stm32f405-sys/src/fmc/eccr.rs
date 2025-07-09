// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ECCR` reader"]
pub type R = crate::R<EccrSpec>;
#[doc = "Register `ECCR` writer"]
pub type W = crate::W<EccrSpec>;
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
    pub fn eccx(&mut self) -> EccxW<EccrSpec> {
        EccxW::new(self, 0)
    }
}
#[doc = "ECC result register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccrSpec;
impl crate::RegisterSpec for EccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`eccr::R`](R) reader structure"]
impl crate::Readable for EccrSpec {}
#[doc = "`reset()` method sets ECCR to value 0"]
impl crate::Resettable for EccrSpec {
    const RESET_VALUE: u32 = 0;
}
