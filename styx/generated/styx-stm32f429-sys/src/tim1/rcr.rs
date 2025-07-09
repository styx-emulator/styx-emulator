// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RCR` reader"]
pub type R = crate::R<RcrSpec>;
#[doc = "Register `RCR` writer"]
pub type W = crate::W<RcrSpec>;
#[doc = "Field `REP` reader - Repetition counter value"]
pub type RepR = crate::FieldReader;
#[doc = "Field `REP` writer - Repetition counter value"]
pub type RepW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Repetition counter value"]
    #[inline(always)]
    pub fn rep(&self) -> RepR {
        RepR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Repetition counter value"]
    #[inline(always)]
    #[must_use]
    pub fn rep(&mut self) -> RepW<RcrSpec> {
        RepW::new(self, 0)
    }
}
#[doc = "repetition counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RcrSpec;
impl crate::RegisterSpec for RcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`rcr::R`](R) reader structure"]
impl crate::Readable for RcrSpec {}
#[doc = "`write(|w| ..)` method takes [`rcr::W`](W) writer structure"]
impl crate::Writable for RcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RCR to value 0"]
impl crate::Resettable for RcrSpec {
    const RESET_VALUE: u32 = 0;
}
