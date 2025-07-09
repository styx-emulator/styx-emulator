// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `timer1currentval` reader"]
pub type R = crate::R<Timer1currentvalSpec>;
#[doc = "Register `timer1currentval` writer"]
pub type W = crate::W<Timer1currentvalSpec>;
#[doc = "Field `timer1currentval` reader - Current value of Timer1."]
pub type Timer1currentvalR = crate::FieldReader<u32>;
#[doc = "Field `timer1currentval` writer - Current value of Timer1."]
pub type Timer1currentvalW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Current value of Timer1."]
    #[inline(always)]
    pub fn timer1currentval(&self) -> Timer1currentvalR {
        Timer1currentvalR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Current value of Timer1."]
    #[inline(always)]
    #[must_use]
    pub fn timer1currentval(&mut self) -> Timer1currentvalW<Timer1currentvalSpec> {
        Timer1currentvalW::new(self, 0)
    }
}
#[doc = "Provides current value of Timer1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1currentval::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Timer1currentvalSpec;
impl crate::RegisterSpec for Timer1currentvalSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`timer1currentval::R`](R) reader structure"]
impl crate::Readable for Timer1currentvalSpec {}
#[doc = "`reset()` method sets timer1currentval to value 0"]
impl crate::Resettable for Timer1currentvalSpec {
    const RESET_VALUE: u32 = 0;
}
