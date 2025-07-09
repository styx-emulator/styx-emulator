// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `IABR2` reader"]
pub type R = crate::R<Iabr2Spec>;
#[doc = "Register `IABR2` writer"]
pub type W = crate::W<Iabr2Spec>;
#[doc = "Field `ACTIVE` reader - ACTIVE"]
pub type ActiveR = crate::FieldReader<u32>;
#[doc = "Field `ACTIVE` writer - ACTIVE"]
pub type ActiveW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - ACTIVE"]
    #[inline(always)]
    pub fn active(&self) -> ActiveR {
        ActiveR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - ACTIVE"]
    #[inline(always)]
    #[must_use]
    pub fn active(&mut self) -> ActiveW<Iabr2Spec> {
        ActiveW::new(self, 0)
    }
}
#[doc = "Interrupt Active Bit Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iabr2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Iabr2Spec;
impl crate::RegisterSpec for Iabr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 520u64;
}
#[doc = "`read()` method returns [`iabr2::R`](R) reader structure"]
impl crate::Readable for Iabr2Spec {}
#[doc = "`reset()` method sets IABR2 to value 0"]
impl crate::Resettable for Iabr2Spec {
    const RESET_VALUE: u32 = 0;
}
