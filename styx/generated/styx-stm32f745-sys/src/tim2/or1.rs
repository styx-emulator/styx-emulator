// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OR1` reader"]
pub type R = crate::R<Or1Spec>;
#[doc = "Register `OR1` writer"]
pub type W = crate::W<Or1Spec>;
#[doc = "Field `ITR1_RMP` reader - Internal trigger 1 remap"]
pub type Itr1RmpR = crate::BitReader;
#[doc = "Field `ITR1_RMP` writer - Internal trigger 1 remap"]
pub type Itr1RmpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ETR1_RMP` reader - External trigger remap"]
pub type Etr1RmpR = crate::BitReader;
#[doc = "Field `ETR1_RMP` writer - External trigger remap"]
pub type Etr1RmpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TI4_RMP` reader - Input Capture 4 remap"]
pub type Ti4RmpR = crate::FieldReader;
#[doc = "Field `TI4_RMP` writer - Input Capture 4 remap"]
pub type Ti4RmpW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Internal trigger 1 remap"]
    #[inline(always)]
    pub fn itr1_rmp(&self) -> Itr1RmpR {
        Itr1RmpR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - External trigger remap"]
    #[inline(always)]
    pub fn etr1_rmp(&self) -> Etr1RmpR {
        Etr1RmpR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:3 - Input Capture 4 remap"]
    #[inline(always)]
    pub fn ti4_rmp(&self) -> Ti4RmpR {
        Ti4RmpR::new(((self.bits >> 2) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Internal trigger 1 remap"]
    #[inline(always)]
    #[must_use]
    pub fn itr1_rmp(&mut self) -> Itr1RmpW<Or1Spec> {
        Itr1RmpW::new(self, 0)
    }
    #[doc = "Bit 1 - External trigger remap"]
    #[inline(always)]
    #[must_use]
    pub fn etr1_rmp(&mut self) -> Etr1RmpW<Or1Spec> {
        Etr1RmpW::new(self, 1)
    }
    #[doc = "Bits 2:3 - Input Capture 4 remap"]
    #[inline(always)]
    #[must_use]
    pub fn ti4_rmp(&mut self) -> Ti4RmpW<Or1Spec> {
        Ti4RmpW::new(self, 2)
    }
}
#[doc = "TIM2 option register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`or1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`or1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Or1Spec;
impl crate::RegisterSpec for Or1Spec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`or1::R`](R) reader structure"]
impl crate::Readable for Or1Spec {}
#[doc = "`write(|w| ..)` method takes [`or1::W`](W) writer structure"]
impl crate::Writable for Or1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OR1 to value 0"]
impl crate::Resettable for Or1Spec {
    const RESET_VALUE: u32 = 0;
}
