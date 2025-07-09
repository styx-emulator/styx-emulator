// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OR2` reader"]
pub type R = crate::R<Or2Spec>;
#[doc = "Register `OR2` writer"]
pub type W = crate::W<Or2Spec>;
#[doc = "Field `ETRSEL` reader - ETR source selection"]
pub type EtrselR = crate::FieldReader;
#[doc = "Field `ETRSEL` writer - ETR source selection"]
pub type EtrselW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 14:16 - ETR source selection"]
    #[inline(always)]
    pub fn etrsel(&self) -> EtrselR {
        EtrselR::new(((self.bits >> 14) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 14:16 - ETR source selection"]
    #[inline(always)]
    #[must_use]
    pub fn etrsel(&mut self) -> EtrselW<Or2Spec> {
        EtrselW::new(self, 14)
    }
}
#[doc = "TIM3 option register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`or2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`or2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Or2Spec;
impl crate::RegisterSpec for Or2Spec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`or2::R`](R) reader structure"]
impl crate::Readable for Or2Spec {}
#[doc = "`write(|w| ..)` method takes [`or2::W`](W) writer structure"]
impl crate::Writable for Or2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OR2 to value 0"]
impl crate::Resettable for Or2Spec {
    const RESET_VALUE: u32 = 0;
}
