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
#[doc = "Register `fifoth` reader"]
pub type R = crate::R<FifothSpec>;
#[doc = "Register `fifoth` writer"]
pub type W = crate::W<FifothSpec>;
#[doc = "Field `tx_wmark` reader - FIFO threshold watermark level when transmitting data to card. When FIFO data count is less than or equal to this number, DMA/FIFO request is raised. If Interrupt is enabled, then interrupt occurs. During end of packet, request or interrupt is generated, regardless of threshold programming. In non-DMA mode, when transmit FIFO threshold (TXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, on last interrupt, host is responsible for filling FIFO with only required remaining bytes (not before FIFO is full or after CIU completes data transfers, because FIFO may not be empty). In DMA mode, at end of packet, if last transfer is less than burst size, DMA controller does single cycles until required bytes are transferred. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: TX_WMark >= 1; Recommended: FIFO_DEPTH/2 = 512; (means less than or equal to 512)"]
pub type TxWmarkR = crate::FieldReader<u16>;
#[doc = "Field `tx_wmark` writer - FIFO threshold watermark level when transmitting data to card. When FIFO data count is less than or equal to this number, DMA/FIFO request is raised. If Interrupt is enabled, then interrupt occurs. During end of packet, request or interrupt is generated, regardless of threshold programming. In non-DMA mode, when transmit FIFO threshold (TXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, on last interrupt, host is responsible for filling FIFO with only required remaining bytes (not before FIFO is full or after CIU completes data transfers, because FIFO may not be empty). In DMA mode, at end of packet, if last transfer is less than burst size, DMA controller does single cycles until required bytes are transferred. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: TX_WMark >= 1; Recommended: FIFO_DEPTH/2 = 512; (means less than or equal to 512)"]
pub type TxWmarkW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `rx_wmark` reader - FIFO threshold watermark level when receiving data to card. When FIFO data count reaches greater than this number, DMA/FIFO request is raised. During end of packet, request is generated regardless of threshold programming in order to complete any remaining data. In non-DMA mode, when receiver FIFO threshold (RXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, interrupt is not generated if threshold programming is larger than any remaining data. It is responsibility of host to read remaining bytes on seeing Data Transfer Done interrupt. In DMA mode, at end of packet, even if remaining bytes are less than threshold, DMA request does single transfers to flush out any remaining bytes before Data Transfer Done interrupt is set. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: RX_WMark &lt;= 1022 Recommended: 511; means greater than (FIFO_DEPTH/2) - 1) NOTE: In DMA mode during CCS time-out, the DMA does not generate the request at the end of packet, even if remaining bytes are less than threshold. In this case, there will be some data left in the FIFO. It is the responsibility of the application to reset the FIFO after the CCS timeout."]
pub type RxWmarkR = crate::FieldReader<u16>;
#[doc = "Field `rx_wmark` writer - FIFO threshold watermark level when receiving data to card. When FIFO data count reaches greater than this number, DMA/FIFO request is raised. During end of packet, request is generated regardless of threshold programming in order to complete any remaining data. In non-DMA mode, when receiver FIFO threshold (RXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, interrupt is not generated if threshold programming is larger than any remaining data. It is responsibility of host to read remaining bytes on seeing Data Transfer Done interrupt. In DMA mode, at end of packet, even if remaining bytes are less than threshold, DMA request does single transfers to flush out any remaining bytes before Data Transfer Done interrupt is set. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: RX_WMark &lt;= 1022 Recommended: 511; means greater than (FIFO_DEPTH/2) - 1) NOTE: In DMA mode during CCS time-out, the DMA does not generate the request at the end of packet, even if remaining bytes are less than threshold. In this case, there will be some data left in the FIFO. It is the responsibility of the application to reset the FIFO after the CCS timeout."]
pub type RxWmarkW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Burst size of multiple transaction; should be programmed same as DMA controller multiple-transaction-size SRC/DEST_MSIZE. The units for transfers is 32 bits. A single transfer would be signalled based on this value. Value should be sub-multiple of 512. Allowed combinations for MSize and TX_WMark.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DwDmaMultipleTransactionSize {
    #[doc = "0: `0`"]
    Txmsize1 = 0,
    #[doc = "1: `1`"]
    Txmsize4 = 1,
    #[doc = "2: `10`"]
    Txmsizek8 = 2,
    #[doc = "3: `11`"]
    Txmsizek16 = 3,
    #[doc = "5: `101`"]
    Rxmsizek1 = 5,
    #[doc = "6: `110`"]
    Rxmsizek4 = 6,
    #[doc = "7: `111`"]
    Rxmsize8 = 7,
}
impl From<DwDmaMultipleTransactionSize> for u8 {
    #[inline(always)]
    fn from(variant: DwDmaMultipleTransactionSize) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for DwDmaMultipleTransactionSize {
    type Ux = u8;
}
#[doc = "Field `dw_dma_multiple_transaction_size` reader - Burst size of multiple transaction; should be programmed same as DMA controller multiple-transaction-size SRC/DEST_MSIZE. The units for transfers is 32 bits. A single transfer would be signalled based on this value. Value should be sub-multiple of 512. Allowed combinations for MSize and TX_WMark."]
pub type DwDmaMultipleTransactionSizeR = crate::FieldReader<DwDmaMultipleTransactionSize>;
impl DwDmaMultipleTransactionSizeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<DwDmaMultipleTransactionSize> {
        match self.bits {
            0 => Some(DwDmaMultipleTransactionSize::Txmsize1),
            1 => Some(DwDmaMultipleTransactionSize::Txmsize4),
            2 => Some(DwDmaMultipleTransactionSize::Txmsizek8),
            3 => Some(DwDmaMultipleTransactionSize::Txmsizek16),
            5 => Some(DwDmaMultipleTransactionSize::Rxmsizek1),
            6 => Some(DwDmaMultipleTransactionSize::Rxmsizek4),
            7 => Some(DwDmaMultipleTransactionSize::Rxmsize8),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_txmsize1(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Txmsize1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_txmsize4(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Txmsize4
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_txmsizek8(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Txmsizek8
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_txmsizek16(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Txmsizek16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_rxmsizek1(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Rxmsizek1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_rxmsizek4(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Rxmsizek4
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_rxmsize8(&self) -> bool {
        *self == DwDmaMultipleTransactionSize::Rxmsize8
    }
}
#[doc = "Field `dw_dma_multiple_transaction_size` writer - Burst size of multiple transaction; should be programmed same as DMA controller multiple-transaction-size SRC/DEST_MSIZE. The units for transfers is 32 bits. A single transfer would be signalled based on this value. Value should be sub-multiple of 512. Allowed combinations for MSize and TX_WMark."]
pub type DwDmaMultipleTransactionSizeW<'a, REG> =
    crate::FieldWriter<'a, REG, 3, DwDmaMultipleTransactionSize>;
impl<'a, REG> DwDmaMultipleTransactionSizeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn txmsize1(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Txmsize1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn txmsize4(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Txmsize4)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn txmsizek8(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Txmsizek8)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn txmsizek16(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Txmsizek16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn rxmsizek1(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Rxmsizek1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn rxmsizek4(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Rxmsizek4)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn rxmsize8(self) -> &'a mut crate::W<REG> {
        self.variant(DwDmaMultipleTransactionSize::Rxmsize8)
    }
}
impl R {
    #[doc = "Bits 0:11 - FIFO threshold watermark level when transmitting data to card. When FIFO data count is less than or equal to this number, DMA/FIFO request is raised. If Interrupt is enabled, then interrupt occurs. During end of packet, request or interrupt is generated, regardless of threshold programming. In non-DMA mode, when transmit FIFO threshold (TXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, on last interrupt, host is responsible for filling FIFO with only required remaining bytes (not before FIFO is full or after CIU completes data transfers, because FIFO may not be empty). In DMA mode, at end of packet, if last transfer is less than burst size, DMA controller does single cycles until required bytes are transferred. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: TX_WMark >= 1; Recommended: FIFO_DEPTH/2 = 512; (means less than or equal to 512)"]
    #[inline(always)]
    pub fn tx_wmark(&self) -> TxWmarkR {
        TxWmarkR::new((self.bits & 0x0fff) as u16)
    }
    #[doc = "Bits 16:27 - FIFO threshold watermark level when receiving data to card. When FIFO data count reaches greater than this number, DMA/FIFO request is raised. During end of packet, request is generated regardless of threshold programming in order to complete any remaining data. In non-DMA mode, when receiver FIFO threshold (RXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, interrupt is not generated if threshold programming is larger than any remaining data. It is responsibility of host to read remaining bytes on seeing Data Transfer Done interrupt. In DMA mode, at end of packet, even if remaining bytes are less than threshold, DMA request does single transfers to flush out any remaining bytes before Data Transfer Done interrupt is set. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: RX_WMark &lt;= 1022 Recommended: 511; means greater than (FIFO_DEPTH/2) - 1) NOTE: In DMA mode during CCS time-out, the DMA does not generate the request at the end of packet, even if remaining bytes are less than threshold. In this case, there will be some data left in the FIFO. It is the responsibility of the application to reset the FIFO after the CCS timeout."]
    #[inline(always)]
    pub fn rx_wmark(&self) -> RxWmarkR {
        RxWmarkR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
    #[doc = "Bits 28:30 - Burst size of multiple transaction; should be programmed same as DMA controller multiple-transaction-size SRC/DEST_MSIZE. The units for transfers is 32 bits. A single transfer would be signalled based on this value. Value should be sub-multiple of 512. Allowed combinations for MSize and TX_WMark."]
    #[inline(always)]
    pub fn dw_dma_multiple_transaction_size(&self) -> DwDmaMultipleTransactionSizeR {
        DwDmaMultipleTransactionSizeR::new(((self.bits >> 28) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:11 - FIFO threshold watermark level when transmitting data to card. When FIFO data count is less than or equal to this number, DMA/FIFO request is raised. If Interrupt is enabled, then interrupt occurs. During end of packet, request or interrupt is generated, regardless of threshold programming. In non-DMA mode, when transmit FIFO threshold (TXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, on last interrupt, host is responsible for filling FIFO with only required remaining bytes (not before FIFO is full or after CIU completes data transfers, because FIFO may not be empty). In DMA mode, at end of packet, if last transfer is less than burst size, DMA controller does single cycles until required bytes are transferred. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: TX_WMark >= 1; Recommended: FIFO_DEPTH/2 = 512; (means less than or equal to 512)"]
    #[inline(always)]
    #[must_use]
    pub fn tx_wmark(&mut self) -> TxWmarkW<FifothSpec> {
        TxWmarkW::new(self, 0)
    }
    #[doc = "Bits 16:27 - FIFO threshold watermark level when receiving data to card. When FIFO data count reaches greater than this number, DMA/FIFO request is raised. During end of packet, request is generated regardless of threshold programming in order to complete any remaining data. In non-DMA mode, when receiver FIFO threshold (RXDR) interrupt is enabled, then interrupt is generated instead of DMA request. During end of packet, interrupt is not generated if threshold programming is larger than any remaining data. It is responsibility of host to read remaining bytes on seeing Data Transfer Done interrupt. In DMA mode, at end of packet, even if remaining bytes are less than threshold, DMA request does single transfers to flush out any remaining bytes before Data Transfer Done interrupt is set. 12 bits - 1 bit less than FIFO-count of status register, which is 13 bits. Limitation: RX_WMark &lt;= 1022 Recommended: 511; means greater than (FIFO_DEPTH/2) - 1) NOTE: In DMA mode during CCS time-out, the DMA does not generate the request at the end of packet, even if remaining bytes are less than threshold. In this case, there will be some data left in the FIFO. It is the responsibility of the application to reset the FIFO after the CCS timeout."]
    #[inline(always)]
    #[must_use]
    pub fn rx_wmark(&mut self) -> RxWmarkW<FifothSpec> {
        RxWmarkW::new(self, 16)
    }
    #[doc = "Bits 28:30 - Burst size of multiple transaction; should be programmed same as DMA controller multiple-transaction-size SRC/DEST_MSIZE. The units for transfers is 32 bits. A single transfer would be signalled based on this value. Value should be sub-multiple of 512. Allowed combinations for MSize and TX_WMark."]
    #[inline(always)]
    #[must_use]
    pub fn dw_dma_multiple_transaction_size(
        &mut self,
    ) -> DwDmaMultipleTransactionSizeW<FifothSpec> {
        DwDmaMultipleTransactionSizeW::new(self, 28)
    }
}
#[doc = "DMA and FIFO Control Fields.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifoth::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifoth::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifothSpec;
impl crate::RegisterSpec for FifothSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`fifoth::R`](R) reader structure"]
impl crate::Readable for FifothSpec {}
#[doc = "`write(|w| ..)` method takes [`fifoth::W`](W) writer structure"]
impl crate::Writable for FifothSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fifoth to value 0x03ff_0000"]
impl crate::Resettable for FifothSpec {
    const RESET_VALUE: u32 = 0x03ff_0000;
}
