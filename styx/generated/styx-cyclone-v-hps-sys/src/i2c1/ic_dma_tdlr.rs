// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_dma_tdlr` reader"]
pub type R = crate::R<IcDmaTdlrSpec>;
#[doc = "Register `ic_dma_tdlr` writer"]
pub type W = crate::W<IcDmaTdlrSpec>;
#[doc = "Field `dmatdl` reader - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the i2c_dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
pub type DmatdlR = crate::FieldReader;
#[doc = "Field `dmatdl` writer - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the i2c_dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
pub type DmatdlW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the i2c_dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
    #[inline(always)]
    pub fn dmatdl(&self) -> DmatdlR {
        DmatdlR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - This bit field controls the level at which a DMA request is made by the transmit logic. It is equal to the watermark level; that is, the i2c_dma_tx_req signal is generated when the number of valid data entries in the transmit FIFO is equal to or below this field value, and TDMAE = 1."]
    #[inline(always)]
    #[must_use]
    pub fn dmatdl(&mut self) -> DmatdlW<IcDmaTdlrSpec> {
        DmatdlW::new(self, 0)
    }
}
#[doc = "This register supports DMA Transmit Operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_dma_tdlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_dma_tdlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcDmaTdlrSpec;
impl crate::RegisterSpec for IcDmaTdlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`ic_dma_tdlr::R`](R) reader structure"]
impl crate::Readable for IcDmaTdlrSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_dma_tdlr::W`](W) writer structure"]
impl crate::Writable for IcDmaTdlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_dma_tdlr to value 0"]
impl crate::Resettable for IcDmaTdlrSpec {
    const RESET_VALUE: u32 = 0;
}
