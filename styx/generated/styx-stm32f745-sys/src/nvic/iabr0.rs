// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `IABR0` reader"]
pub type R = crate::R<Iabr0Spec>;
#[doc = "Register `IABR0` writer"]
pub type W = crate::W<Iabr0Spec>;
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
    pub fn active(&mut self) -> ActiveW<Iabr0Spec> {
        ActiveW::new(self, 0)
    }
}
#[doc = "Interrupt Active Bit Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iabr0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Iabr0Spec;
impl crate::RegisterSpec for Iabr0Spec {
    type Ux = u32;
    const OFFSET: u64 = 512u64;
}
#[doc = "`read()` method returns [`iabr0::R`](R) reader structure"]
impl crate::Readable for Iabr0Spec {}
#[doc = "`reset()` method sets IABR0 to value 0"]
impl crate::Resettable for Iabr0Spec {
    const RESET_VALUE: u32 = 0;
}
