// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SMPR1` reader"]
pub type R = crate::R<Smpr1Spec>;
#[doc = "Register `SMPR1` writer"]
pub type W = crate::W<Smpr1Spec>;
#[doc = "Field `SMPx_x` reader - Sample time bits"]
pub type SmpxXR = crate::FieldReader<u32>;
#[doc = "Field `SMPx_x` writer - Sample time bits"]
pub type SmpxXW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Sample time bits"]
    #[inline(always)]
    pub fn smpx_x(&self) -> SmpxXR {
        SmpxXR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Sample time bits"]
    #[inline(always)]
    #[must_use]
    pub fn smpx_x(&mut self) -> SmpxXW<Smpr1Spec> {
        SmpxXW::new(self, 0)
    }
}
#[doc = "sample time register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`smpr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`smpr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Smpr1Spec;
impl crate::RegisterSpec for Smpr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`smpr1::R`](R) reader structure"]
impl crate::Readable for Smpr1Spec {}
#[doc = "`write(|w| ..)` method takes [`smpr1::W`](W) writer structure"]
impl crate::Writable for Smpr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SMPR1 to value 0"]
impl crate::Resettable for Smpr1Spec {
    const RESET_VALUE: u32 = 0;
}
