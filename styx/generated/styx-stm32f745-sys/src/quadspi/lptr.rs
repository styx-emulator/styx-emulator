// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LPTR` reader"]
pub type R = crate::R<LptrSpec>;
#[doc = "Register `LPTR` writer"]
pub type W = crate::W<LptrSpec>;
#[doc = "Field `TIMEOUT` reader - Timeout period"]
pub type TimeoutR = crate::FieldReader<u16>;
#[doc = "Field `TIMEOUT` writer - Timeout period"]
pub type TimeoutW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Timeout period"]
    #[inline(always)]
    pub fn timeout(&self) -> TimeoutR {
        TimeoutR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Timeout period"]
    #[inline(always)]
    #[must_use]
    pub fn timeout(&mut self) -> TimeoutW<LptrSpec> {
        TimeoutW::new(self, 0)
    }
}
#[doc = "low-power timeout register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lptr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lptr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LptrSpec;
impl crate::RegisterSpec for LptrSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`lptr::R`](R) reader structure"]
impl crate::Readable for LptrSpec {}
#[doc = "`write(|w| ..)` method takes [`lptr::W`](W) writer structure"]
impl crate::Writable for LptrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets LPTR to value 0"]
impl crate::Resettable for LptrSpec {
    const RESET_VALUE: u32 = 0;
}
