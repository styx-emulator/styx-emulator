// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmatdlr` reader"]
pub type R = crate::R<DmatdlrSpec>;
#[doc = "Register `dmatdlr` writer"]
pub type W = crate::W<DmatdlrSpec>;
#[doc = "Field `dmatdl` reader - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
pub type DmatdlR = crate::FieldReader;
#[doc = "Field `dmatdl` writer - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
pub type DmatdlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
    #[inline(always)]
    pub fn dmatdl(&self) -> DmatdlR {
        DmatdlR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
    #[inline(always)]
    #[must_use]
    pub fn dmatdl(&mut self) -> DmatdlW<DmatdlrSpec> {
        DmatdlW::new(self, 0)
    }
}
#[doc = "Controls the FIFO Level for a DMA transmit request\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmatdlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmatdlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmatdlrSpec;
impl crate::RegisterSpec for DmatdlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`dmatdlr::R`](R) reader structure"]
impl crate::Readable for DmatdlrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmatdlr::W`](W) writer structure"]
impl crate::Writable for DmatdlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmatdlr to value 0"]
impl crate::Resettable for DmatdlrSpec {
    const RESET_VALUE: u32 = 0;
}
