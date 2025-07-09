// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DHR8R2` reader"]
pub type R = crate::R<Dhr8r2Spec>;
#[doc = "Register `DHR8R2` writer"]
pub type W = crate::W<Dhr8r2Spec>;
#[doc = "Field `DACC2DHR` reader - DAC channel2 8-bit right-aligned data"]
pub type Dacc2dhrR = crate::FieldReader;
#[doc = "Field `DACC2DHR` writer - DAC channel2 8-bit right-aligned data"]
pub type Dacc2dhrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - DAC channel2 8-bit right-aligned data"]
    #[inline(always)]
    pub fn dacc2dhr(&self) -> Dacc2dhrR {
        Dacc2dhrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - DAC channel2 8-bit right-aligned data"]
    #[inline(always)]
    #[must_use]
    pub fn dacc2dhr(&mut self) -> Dacc2dhrW<Dhr8r2Spec> {
        Dacc2dhrW::new(self, 0)
    }
}
#[doc = "channel2 8-bit right-aligned data holding register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dhr8r2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dhr8r2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dhr8r2Spec;
impl crate::RegisterSpec for Dhr8r2Spec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`dhr8r2::R`](R) reader structure"]
impl crate::Readable for Dhr8r2Spec {}
#[doc = "`write(|w| ..)` method takes [`dhr8r2::W`](W) writer structure"]
impl crate::Writable for Dhr8r2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DHR8R2 to value 0"]
impl crate::Resettable for Dhr8r2Spec {
    const RESET_VALUE: u32 = 0;
}
