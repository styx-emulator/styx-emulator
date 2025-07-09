// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_dma_intr` reader"]
pub type R = crate::R<DmaDmaIntrSpec>;
#[doc = "Register `dma_dma_intr` writer"]
pub type W = crate::W<DmaDmaIntrSpec>;
#[doc = "Field `target_error` reader - Controller initiator interface received an ERROR target response for a transaction."]
pub type TargetErrorR = crate::BitReader;
#[doc = "Field `target_error` writer - Controller initiator interface received an ERROR target response for a transaction."]
pub type TargetErrorW<'a, REG> = crate::BitWriter1C<'a, REG>;
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
    pub fn target_error(&mut self) -> TargetErrorW<DmaDmaIntrSpec> {
        TargetErrorW::new(self, 0)
    }
}
#[doc = "DMA interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_dma_intr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_dma_intr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaDmaIntrSpec;
impl crate::RegisterSpec for DmaDmaIntrSpec {
    type Ux = u32;
    const OFFSET: u64 = 1824u64;
}
#[doc = "`read()` method returns [`dma_dma_intr::R`](R) reader structure"]
impl crate::Readable for DmaDmaIntrSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_dma_intr::W`](W) writer structure"]
impl crate::Writable for DmaDmaIntrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x01;
}
#[doc = "`reset()` method sets dma_dma_intr to value 0"]
impl crate::Resettable for DmaDmaIntrSpec {
    const RESET_VALUE: u32 = 0;
}
