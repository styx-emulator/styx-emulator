// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RLR` reader"]
pub type R = crate::R<RlrSpec>;
#[doc = "Register `RLR` writer"]
pub type W = crate::W<RlrSpec>;
#[doc = "Field `RL` reader - Watchdog counter reload value"]
pub type RlR = crate::FieldReader<u16>;
#[doc = "Field `RL` writer - Watchdog counter reload value"]
pub type RlW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Watchdog counter reload value"]
    #[inline(always)]
    pub fn rl(&self) -> RlR {
        RlR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Watchdog counter reload value"]
    #[inline(always)]
    #[must_use]
    pub fn rl(&mut self) -> RlW<RlrSpec> {
        RlW::new(self, 0)
    }
}
#[doc = "Reload register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RlrSpec;
impl crate::RegisterSpec for RlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`rlr::R`](R) reader structure"]
impl crate::Readable for RlrSpec {}
#[doc = "`write(|w| ..)` method takes [`rlr::W`](W) writer structure"]
impl crate::Writable for RlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RLR to value 0x0fff"]
impl crate::Resettable for RlrSpec {
    const RESET_VALUE: u32 = 0x0fff;
}
