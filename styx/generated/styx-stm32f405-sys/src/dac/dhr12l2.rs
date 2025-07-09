// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DHR12L2` reader"]
pub type R = crate::R<Dhr12l2Spec>;
#[doc = "Register `DHR12L2` writer"]
pub type W = crate::W<Dhr12l2Spec>;
#[doc = "Field `DACC2DHR` reader - DAC channel2 12-bit left-aligned data"]
pub type Dacc2dhrR = crate::FieldReader<u16>;
#[doc = "Field `DACC2DHR` writer - DAC channel2 12-bit left-aligned data"]
pub type Dacc2dhrW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 4:15 - DAC channel2 12-bit left-aligned data"]
    #[inline(always)]
    pub fn dacc2dhr(&self) -> Dacc2dhrR {
        Dacc2dhrR::new(((self.bits >> 4) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 4:15 - DAC channel2 12-bit left-aligned data"]
    #[inline(always)]
    #[must_use]
    pub fn dacc2dhr(&mut self) -> Dacc2dhrW<Dhr12l2Spec> {
        Dacc2dhrW::new(self, 4)
    }
}
#[doc = "channel2 12-bit left aligned data holding register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dhr12l2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dhr12l2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dhr12l2Spec;
impl crate::RegisterSpec for Dhr12l2Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`dhr12l2::R`](R) reader structure"]
impl crate::Readable for Dhr12l2Spec {}
#[doc = "`write(|w| ..)` method takes [`dhr12l2::W`](W) writer structure"]
impl crate::Writable for Dhr12l2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DHR12L2 to value 0"]
impl crate::Resettable for Dhr12l2Spec {
    const RESET_VALUE: u32 = 0;
}
