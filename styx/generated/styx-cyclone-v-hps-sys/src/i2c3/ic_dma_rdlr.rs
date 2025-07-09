// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `ic_dma_rdlr` reader"]
pub type R = crate::R<IcDmaRdlrSpec>;
#[doc = "Register `ic_dma_rdlr` writer"]
pub type W = crate::W<IcDmaRdlrSpec>;
#[doc = "Field `dmardl` reader - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level \\= DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or more than this field value + 1, and RDMAE =1. For instance, when DMARDL is 0, then dma_rx_req is asserted when or more data entries are present in the receive FIFO."]
pub type DmardlR = crate::FieldReader;
#[doc = "Field `dmardl` writer - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level \\= DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or more than this field value + 1, and RDMAE =1. For instance, when DMARDL is 0, then dma_rx_req is asserted when or more data entries are present in the receive FIFO."]
pub type DmardlW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level \\= DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or more than this field value + 1, and RDMAE =1. For instance, when DMARDL is 0, then dma_rx_req is asserted when or more data entries are present in the receive FIFO."]
    #[inline(always)]
    pub fn dmardl(&self) -> DmardlR {
        DmardlR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - This bit field controls the level at which a DMA request is made by the receive logic. The watermark level \\= DMARDL+1; that is, dma_rx_req is generated when the number of valid data entries in the receive FIFO is equal to or more than this field value + 1, and RDMAE =1. For instance, when DMARDL is 0, then dma_rx_req is asserted when or more data entries are present in the receive FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn dmardl(&mut self) -> DmardlW<IcDmaRdlrSpec> {
        DmardlW::new(self, 0)
    }
}
#[doc = "DMA Control Signals Interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_dma_rdlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_dma_rdlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcDmaRdlrSpec;
impl crate::RegisterSpec for IcDmaRdlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`ic_dma_rdlr::R`](R) reader structure"]
impl crate::Readable for IcDmaRdlrSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_dma_rdlr::W`](W) writer structure"]
impl crate::Writable for IcDmaRdlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_dma_rdlr to value 0"]
impl crate::Resettable for IcDmaRdlrSpec {
    const RESET_VALUE: u32 = 0;
}
