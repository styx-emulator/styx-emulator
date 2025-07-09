// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PIR` reader"]
pub type R = crate::R<PirSpec>;
#[doc = "Register `PIR` writer"]
pub type W = crate::W<PirSpec>;
#[doc = "Field `INTERVAL` reader - Polling interval"]
pub type IntervalR = crate::FieldReader<u16>;
#[doc = "Field `INTERVAL` writer - Polling interval"]
pub type IntervalW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Polling interval"]
    #[inline(always)]
    pub fn interval(&self) -> IntervalR {
        IntervalR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Polling interval"]
    #[inline(always)]
    #[must_use]
    pub fn interval(&mut self) -> IntervalW<PirSpec> {
        IntervalW::new(self, 0)
    }
}
#[doc = "polling interval register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pir::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pir::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PirSpec;
impl crate::RegisterSpec for PirSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`pir::R`](R) reader structure"]
impl crate::Readable for PirSpec {}
#[doc = "`write(|w| ..)` method takes [`pir::W`](W) writer structure"]
impl crate::Writable for PirSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PIR to value 0"]
impl crate::Resettable for PirSpec {
    const RESET_VALUE: u32 = 0;
}
