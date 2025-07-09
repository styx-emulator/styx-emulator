// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HTR` reader"]
pub type R = crate::R<HtrSpec>;
#[doc = "Register `HTR` writer"]
pub type W = crate::W<HtrSpec>;
#[doc = "Field `HT` reader - Analog watchdog higher threshold"]
pub type HtR = crate::FieldReader<u16>;
#[doc = "Field `HT` writer - Analog watchdog higher threshold"]
pub type HtW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Analog watchdog higher threshold"]
    #[inline(always)]
    pub fn ht(&self) -> HtR {
        HtR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Analog watchdog higher threshold"]
    #[inline(always)]
    #[must_use]
    pub fn ht(&mut self) -> HtW<HtrSpec> {
        HtW::new(self, 0)
    }
}
#[doc = "watchdog higher threshold register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`htr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`htr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HtrSpec;
impl crate::RegisterSpec for HtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`htr::R`](R) reader structure"]
impl crate::Readable for HtrSpec {}
#[doc = "`write(|w| ..)` method takes [`htr::W`](W) writer structure"]
impl crate::Writable for HtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets HTR to value 0x0fff"]
impl crate::Resettable for HtrSpec {
    const RESET_VALUE: u32 = 0x0fff;
}
