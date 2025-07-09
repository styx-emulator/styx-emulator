// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmardlr` reader"]
pub type R = crate::R<DmardlrSpec>;
#[doc = "Register `dmardlr` writer"]
pub type W = crate::W<DmardlrSpec>;
#[doc = "Field `dmardl` reader - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level = DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or above this field value + 1, and RDMAE=1."]
pub type DmardlR = crate::FieldReader;
#[doc = "Field `dmardl` writer - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level = DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or above this field value + 1, and RDMAE=1."]
pub type DmardlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level = DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or above this field value + 1, and RDMAE=1."]
    #[inline(always)]
    pub fn dmardl(&self) -> DmardlR {
        DmardlR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level = DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or above this field value + 1, and RDMAE=1."]
    #[inline(always)]
    #[must_use]
    pub fn dmardl(&mut self) -> DmardlW<DmardlrSpec> {
        DmardlW::new(self, 0)
    }
}
#[doc = "Controls DMA Receive FIFO Threshold\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmardlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmardlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmardlrSpec;
impl crate::RegisterSpec for DmardlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`dmardlr::R`](R) reader structure"]
impl crate::Readable for DmardlrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmardlr::W`](W) writer structure"]
impl crate::Writable for DmardlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmardlr to value 0"]
impl crate::Resettable for DmardlrSpec {
    const RESET_VALUE: u32 = 0;
}
