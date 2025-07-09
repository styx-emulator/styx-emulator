// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RESPCMD` reader"]
pub type R = crate::R<RespcmdSpec>;
#[doc = "Register `RESPCMD` writer"]
pub type W = crate::W<RespcmdSpec>;
#[doc = "Field `RESPCMD` reader - Response command index"]
pub type RespcmdR = crate::FieldReader;
#[doc = "Field `RESPCMD` writer - Response command index"]
pub type RespcmdW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - Response command index"]
    #[inline(always)]
    pub fn respcmd(&self) -> RespcmdR {
        RespcmdR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - Response command index"]
    #[inline(always)]
    #[must_use]
    pub fn respcmd(&mut self) -> RespcmdW<RespcmdSpec> {
        RespcmdW::new(self, 0)
    }
}
#[doc = "command response register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`respcmd::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RespcmdSpec;
impl crate::RegisterSpec for RespcmdSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`respcmd::R`](R) reader structure"]
impl crate::Readable for RespcmdSpec {}
#[doc = "`reset()` method sets RESPCMD to value 0"]
impl crate::Resettable for RespcmdSpec {
    const RESET_VALUE: u32 = 0;
}
