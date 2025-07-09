// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_dma_intr_en` reader"]
pub type R = crate::R<DmaDmaIntrEnSpec>;
#[doc = "Register `dma_dma_intr_en` writer"]
pub type W = crate::W<DmaDmaIntrEnSpec>;
#[doc = "Field `target_error` reader - Controller initiator interface received an ERROR target response for a transaction."]
pub type TargetErrorR = crate::BitReader;
#[doc = "Field `target_error` writer - Controller initiator interface received an ERROR target response for a transaction."]
pub type TargetErrorW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Controller initiator interface received an ERROR target response for a transaction."]
    #[inline(always)]
    pub fn target_error(&self) -> TargetErrorR {
        TargetErrorR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controller initiator interface received an ERROR target response for a transaction."]
    #[inline(always)]
    #[must_use]
    pub fn target_error(&mut self) -> TargetErrorW<DmaDmaIntrEnSpec> {
        TargetErrorW::new(self, 0)
    }
}
#[doc = "Enables corresponding interrupt bit in dma interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_dma_intr_en::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_dma_intr_en::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaDmaIntrEnSpec;
impl crate::RegisterSpec for DmaDmaIntrEnSpec {
    type Ux = u32;
    const OFFSET: u64 = 1840u64;
}
#[doc = "`read()` method returns [`dma_dma_intr_en::R`](R) reader structure"]
impl crate::Readable for DmaDmaIntrEnSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_dma_intr_en::W`](W) writer structure"]
impl crate::Writable for DmaDmaIntrEnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dma_dma_intr_en to value 0"]
impl crate::Resettable for DmaDmaIntrEnSpec {
    const RESET_VALUE: u32 = 0;
}
