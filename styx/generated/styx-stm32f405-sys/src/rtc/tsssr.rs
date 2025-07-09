// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TSSSR` reader"]
pub type R = crate::R<TsssrSpec>;
#[doc = "Register `TSSSR` writer"]
pub type W = crate::W<TsssrSpec>;
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
    pub fn ss(&mut self) -> SsW<TsssrSpec> {
        SsW::new(self, 0)
    }
}
#[doc = "timestamp sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tsssr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TsssrSpec;
impl crate::RegisterSpec for TsssrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`tsssr::R`](R) reader structure"]
impl crate::Readable for TsssrSpec {}
#[doc = "`reset()` method sets TSSSR to value 0"]
impl crate::Resettable for TsssrSpec {
    const RESET_VALUE: u32 = 0;
}
