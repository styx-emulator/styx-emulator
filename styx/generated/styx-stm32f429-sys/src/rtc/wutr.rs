// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `WUTR` reader"]
pub type R = crate::R<WutrSpec>;
#[doc = "Register `WUTR` writer"]
pub type W = crate::W<WutrSpec>;
#[doc = "Field `WUT` reader - Wakeup auto-reload value bits"]
pub type WutR = crate::FieldReader<u16>;
#[doc = "Field `WUT` writer - Wakeup auto-reload value bits"]
pub type WutW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Wakeup auto-reload value bits"]
    #[inline(always)]
    pub fn wut(&self) -> WutR {
        WutR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Wakeup auto-reload value bits"]
    #[inline(always)]
    #[must_use]
    pub fn wut(&mut self) -> WutW<WutrSpec> {
        WutW::new(self, 0)
    }
}
#[doc = "wakeup timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wutr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wutr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WutrSpec;
impl crate::RegisterSpec for WutrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`wutr::R`](R) reader structure"]
impl crate::Readable for WutrSpec {}
#[doc = "`write(|w| ..)` method takes [`wutr::W`](W) writer structure"]
impl crate::Writable for WutrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets WUTR to value 0xffff"]
impl crate::Resettable for WutrSpec {
    const RESET_VALUE: u32 = 0xffff;
}
