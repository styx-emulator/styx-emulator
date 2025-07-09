// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `timer1eoi` reader"]
pub type R = crate::R<Timer1eoiSpec>;
#[doc = "Register `timer1eoi` writer"]
pub type W = crate::W<Timer1eoiSpec>;
#[doc = "Field `timer1eoi` reader - Reading from this register clears the interrupt from Timer1 and returns 0."]
pub type Timer1eoiR = crate::BitReader;
#[doc = "Field `timer1eoi` writer - Reading from this register clears the interrupt from Timer1 and returns 0."]
pub type Timer1eoiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Reading from this register clears the interrupt from Timer1 and returns 0."]
    #[inline(always)]
    pub fn timer1eoi(&self) -> Timer1eoiR {
        Timer1eoiR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Reading from this register clears the interrupt from Timer1 and returns 0."]
    #[inline(always)]
    #[must_use]
    pub fn timer1eoi(&mut self) -> Timer1eoiW<Timer1eoiSpec> {
        Timer1eoiW::new(self, 0)
    }
}
#[doc = "Clears Timer1 interrupt when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1eoi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Timer1eoiSpec;
impl crate::RegisterSpec for Timer1eoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`timer1eoi::R`](R) reader structure"]
impl crate::Readable for Timer1eoiSpec {}
#[doc = "`reset()` method sets timer1eoi to value 0"]
impl crate::Resettable for Timer1eoiSpec {
    const RESET_VALUE: u32 = 0;
}
