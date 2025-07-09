// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LWR` reader"]
pub type R = crate::R<LwrSpec>;
#[doc = "Register `LWR` writer"]
pub type W = crate::W<LwrSpec>;
#[doc = "Field `LW` reader - Line watermark"]
pub type LwR = crate::FieldReader<u16>;
#[doc = "Field `LW` writer - Line watermark"]
pub type LwW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Line watermark"]
    #[inline(always)]
    pub fn lw(&self) -> LwR {
        LwR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Line watermark"]
    #[inline(always)]
    #[must_use]
    pub fn lw(&mut self) -> LwW<LwrSpec> {
        LwW::new(self, 0)
    }
}
#[doc = "line watermark register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lwr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lwr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LwrSpec;
impl crate::RegisterSpec for LwrSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`lwr::R`](R) reader structure"]
impl crate::Readable for LwrSpec {}
#[doc = "`write(|w| ..)` method takes [`lwr::W`](W) writer structure"]
impl crate::Writable for LwrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets LWR to value 0"]
impl crate::Resettable for LwrSpec {
    const RESET_VALUE: u32 = 0;
}
