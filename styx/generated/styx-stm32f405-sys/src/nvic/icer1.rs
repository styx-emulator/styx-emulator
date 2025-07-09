// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ICER1` reader"]
pub type R = crate::R<Icer1Spec>;
#[doc = "Register `ICER1` writer"]
pub type W = crate::W<Icer1Spec>;
#[doc = "Field `CLRENA` reader - CLRENA"]
pub type ClrenaR = crate::FieldReader<u32>;
#[doc = "Field `CLRENA` writer - CLRENA"]
pub type ClrenaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CLRENA"]
    #[inline(always)]
    pub fn clrena(&self) -> ClrenaR {
        ClrenaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CLRENA"]
    #[inline(always)]
    #[must_use]
    pub fn clrena(&mut self) -> ClrenaW<Icer1Spec> {
        ClrenaW::new(self, 0)
    }
}
#[doc = "Interrupt Clear-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icer1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icer1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Icer1Spec;
impl crate::RegisterSpec for Icer1Spec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`icer1::R`](R) reader structure"]
impl crate::Readable for Icer1Spec {}
#[doc = "`write(|w| ..)` method takes [`icer1::W`](W) writer structure"]
impl crate::Writable for Icer1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ICER1 to value 0"]
impl crate::Resettable for Icer1Spec {
    const RESET_VALUE: u32 = 0;
}
