// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `timer1loadcount` reader"]
pub type R = crate::R<Timer1loadcountSpec>;
#[doc = "Register `timer1loadcount` writer"]
pub type W = crate::W<Timer1loadcountSpec>;
#[doc = "Field `timer1loadcount` reader - Value to be loaded into Timer1. This is the value from which counting commences. Any value written to this register is loaded into the associated timer."]
pub type Timer1loadcountR = crate::FieldReader<u32>;
#[doc = "Field `timer1loadcount` writer - Value to be loaded into Timer1. This is the value from which counting commences. Any value written to this register is loaded into the associated timer."]
pub type Timer1loadcountW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Value to be loaded into Timer1. This is the value from which counting commences. Any value written to this register is loaded into the associated timer."]
    #[inline(always)]
    pub fn timer1loadcount(&self) -> Timer1loadcountR {
        Timer1loadcountR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Value to be loaded into Timer1. This is the value from which counting commences. Any value written to this register is loaded into the associated timer."]
    #[inline(always)]
    #[must_use]
    pub fn timer1loadcount(&mut self) -> Timer1loadcountW<Timer1loadcountSpec> {
        Timer1loadcountW::new(self, 0)
    }
}
#[doc = "Used to load counter value into Timer1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1loadcount::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`timer1loadcount::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Timer1loadcountSpec;
impl crate::RegisterSpec for Timer1loadcountSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`timer1loadcount::R`](R) reader structure"]
impl crate::Readable for Timer1loadcountSpec {}
#[doc = "`write(|w| ..)` method takes [`timer1loadcount::W`](W) writer structure"]
impl crate::Writable for Timer1loadcountSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets timer1loadcount to value 0"]
impl crate::Resettable for Timer1loadcountSpec {
    const RESET_VALUE: u32 = 0;
}
