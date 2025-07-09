// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `timerseoi` reader"]
pub type R = crate::R<TimerseoiSpec>;
#[doc = "Register `timerseoi` writer"]
pub type W = crate::W<TimerseoiSpec>;
#[doc = "Field `timerseoi` reader - Reading from this register clears the interrupt all timers and returns 0. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi."]
pub type TimerseoiR = crate::BitReader;
#[doc = "Field `timerseoi` writer - Reading from this register clears the interrupt all timers and returns 0. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi."]
pub type TimerseoiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Reading from this register clears the interrupt all timers and returns 0. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi."]
    #[inline(always)]
    pub fn timerseoi(&self) -> TimerseoiR {
        TimerseoiR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Reading from this register clears the interrupt all timers and returns 0. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi."]
    #[inline(always)]
    #[must_use]
    pub fn timerseoi(&mut self) -> TimerseoiW<TimerseoiSpec> {
        TimerseoiW::new(self, 0)
    }
}
#[doc = "Clears Timer1 interrupt when read. Because there is only Timer1 in this module instance, reading this register has the same effect as reading timer1eoi.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timerseoi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimerseoiSpec;
impl crate::RegisterSpec for TimerseoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 164u64;
}
#[doc = "`read()` method returns [`timerseoi::R`](R) reader structure"]
impl crate::Readable for TimerseoiSpec {}
#[doc = "`reset()` method sets timerseoi to value 0"]
impl crate::Resettable for TimerseoiSpec {
    const RESET_VALUE: u32 = 0;
}
