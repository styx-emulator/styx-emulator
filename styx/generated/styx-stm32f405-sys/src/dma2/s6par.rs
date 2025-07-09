// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `S6PAR` reader"]
pub type R = crate::R<S6parSpec>;
#[doc = "Register `S6PAR` writer"]
pub type W = crate::W<S6parSpec>;
#[doc = "Field `PA` reader - Peripheral address"]
pub type PaR = crate::FieldReader<u32>;
#[doc = "Field `PA` writer - Peripheral address"]
pub type PaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Peripheral address"]
    #[inline(always)]
    pub fn pa(&self) -> PaR {
        PaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Peripheral address"]
    #[inline(always)]
    #[must_use]
    pub fn pa(&mut self) -> PaW<S6parSpec> {
        PaW::new(self, 0)
    }
}
#[doc = "stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s6par::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s6par::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S6parSpec;
impl crate::RegisterSpec for S6parSpec {
    type Ux = u32;
    const OFFSET: u64 = 168u64;
}
#[doc = "`read()` method returns [`s6par::R`](R) reader structure"]
impl crate::Readable for S6parSpec {}
#[doc = "`write(|w| ..)` method takes [`s6par::W`](W) writer structure"]
impl crate::Writable for S6parSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S6PAR to value 0"]
impl crate::Resettable for S6parSpec {
    const RESET_VALUE: u32 = 0;
}
