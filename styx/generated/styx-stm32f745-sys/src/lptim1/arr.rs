// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ARR` reader"]
pub type R = crate::R<ArrSpec>;
#[doc = "Register `ARR` writer"]
pub type W = crate::W<ArrSpec>;
#[doc = "Field `ARR` reader - Auto reload value"]
pub type ArrR = crate::FieldReader<u16>;
#[doc = "Field `ARR` writer - Auto reload value"]
pub type ArrW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Auto reload value"]
    #[inline(always)]
    pub fn arr(&self) -> ArrR {
        ArrR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Auto reload value"]
    #[inline(always)]
    #[must_use]
    pub fn arr(&mut self) -> ArrW<ArrSpec> {
        ArrW::new(self, 0)
    }
}
#[doc = "Autoreload Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`arr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`arr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ArrSpec;
impl crate::RegisterSpec for ArrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`arr::R`](R) reader structure"]
impl crate::Readable for ArrSpec {}
#[doc = "`write(|w| ..)` method takes [`arr::W`](W) writer structure"]
impl crate::Writable for ArrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ARR to value 0x01"]
impl crate::Resettable for ArrSpec {
    const RESET_VALUE: u32 = 0x01;
}
