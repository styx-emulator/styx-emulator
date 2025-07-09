// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `timerscompversion` reader"]
pub type R = crate::R<TimerscompversionSpec>;
#[doc = "Register `timerscompversion` writer"]
pub type W = crate::W<TimerscompversionSpec>;
#[doc = "Field `timerscompversion` reader - Current revision number of the timers component."]
pub type TimerscompversionR = crate::FieldReader<u32>;
#[doc = "Field `timerscompversion` writer - Current revision number of the timers component."]
pub type TimerscompversionW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Current revision number of the timers component."]
    #[inline(always)]
    pub fn timerscompversion(&self) -> TimerscompversionR {
        TimerscompversionR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Current revision number of the timers component."]
    #[inline(always)]
    #[must_use]
    pub fn timerscompversion(&mut self) -> TimerscompversionW<TimerscompversionSpec> {
        TimerscompversionW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timerscompversion::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimerscompversionSpec;
impl crate::RegisterSpec for TimerscompversionSpec {
    type Ux = u32;
    const OFFSET: u64 = 172u64;
}
#[doc = "`read()` method returns [`timerscompversion::R`](R) reader structure"]
impl crate::Readable for TimerscompversionSpec {}
#[doc = "`reset()` method sets timerscompversion to value 0x3230_352a"]
impl crate::Resettable for TimerscompversionSpec {
    const RESET_VALUE: u32 = 0x3230_352a;
}
