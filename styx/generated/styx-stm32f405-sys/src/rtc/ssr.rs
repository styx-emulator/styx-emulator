// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SSR` reader"]
pub type R = crate::R<SsrSpec>;
#[doc = "Register `SSR` writer"]
pub type W = crate::W<SsrSpec>;
#[doc = "Field `SS` reader - Sub second value"]
pub type SsR = crate::FieldReader<u16>;
#[doc = "Field `SS` writer - Sub second value"]
pub type SsW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Sub second value"]
    #[inline(always)]
    pub fn ss(&self) -> SsR {
        SsR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Sub second value"]
    #[inline(always)]
    #[must_use]
    pub fn ss(&mut self) -> SsW<SsrSpec> {
        SsW::new(self, 0)
    }
}
#[doc = "sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ssr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SsrSpec;
impl crate::RegisterSpec for SsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`ssr::R`](R) reader structure"]
impl crate::Readable for SsrSpec {}
#[doc = "`reset()` method sets SSR to value 0"]
impl crate::Resettable for SsrSpec {
    const RESET_VALUE: u32 = 0;
}
