// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `WPR` reader"]
pub type R = crate::R<WprSpec>;
#[doc = "Register `WPR` writer"]
pub type W = crate::W<WprSpec>;
#[doc = "Field `KEY` reader - Write protection key"]
pub type KeyR = crate::FieldReader;
#[doc = "Field `KEY` writer - Write protection key"]
pub type KeyW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Write protection key"]
    #[inline(always)]
    pub fn key(&self) -> KeyR {
        KeyR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Write protection key"]
    #[inline(always)]
    #[must_use]
    pub fn key(&mut self) -> KeyW<WprSpec> {
        KeyW::new(self, 0)
    }
}
#[doc = "write protection register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wpr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WprSpec;
impl crate::RegisterSpec for WprSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`write(|w| ..)` method takes [`wpr::W`](W) writer structure"]
impl crate::Writable for WprSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets WPR to value 0"]
impl crate::Resettable for WprSpec {
    const RESET_VALUE: u32 = 0;
}
