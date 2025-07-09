// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LTR` reader"]
pub type R = crate::R<LtrSpec>;
#[doc = "Register `LTR` writer"]
pub type W = crate::W<LtrSpec>;
#[doc = "Field `LT` reader - Analog watchdog lower threshold"]
pub type LtR = crate::FieldReader<u16>;
#[doc = "Field `LT` writer - Analog watchdog lower threshold"]
pub type LtW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Analog watchdog lower threshold"]
    #[inline(always)]
    pub fn lt(&self) -> LtR {
        LtR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Analog watchdog lower threshold"]
    #[inline(always)]
    #[must_use]
    pub fn lt(&mut self) -> LtW<LtrSpec> {
        LtW::new(self, 0)
    }
}
#[doc = "watchdog lower threshold register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ltr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ltr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LtrSpec;
impl crate::RegisterSpec for LtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`ltr::R`](R) reader structure"]
impl crate::Readable for LtrSpec {}
#[doc = "`write(|w| ..)` method takes [`ltr::W`](W) writer structure"]
impl crate::Writable for LtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets LTR to value 0"]
impl crate::Resettable for LtrSpec {
    const RESET_VALUE: u32 = 0;
}
