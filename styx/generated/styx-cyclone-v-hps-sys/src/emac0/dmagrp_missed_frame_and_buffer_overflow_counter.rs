// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Missed_Frame_And_Buffer_Overflow_Counter` reader"]
pub type R = crate::R<DmagrpMissedFrameAndBufferOverflowCounterSpec>;
#[doc = "Register `dmagrp_Missed_Frame_And_Buffer_Overflow_Counter` writer"]
pub type W = crate::W<DmagrpMissedFrameAndBufferOverflowCounterSpec>;
#[doc = "Field `misfrmcnt` reader - This field indicates the number of frames missed by the controller because of the Host Receive Buffer being unavailable. This counter is incremented each time the DMA discards an incoming frame. The counter is cleared when this register is read with mci_be_i\\[0\\]
at 1'b1."]
pub type MisfrmcntR = crate::FieldReader<u16>;
#[doc = "Field `misfrmcnt` writer - This field indicates the number of frames missed by the controller because of the Host Receive Buffer being unavailable. This counter is incremented each time the DMA discards an incoming frame. The counter is cleared when this register is read with mci_be_i\\[0\\]
at 1'b1."]
pub type MisfrmcntW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `miscntovf` reader - Overflow bit for Missed Frame Counter"]
pub type MiscntovfR = crate::BitReader;
#[doc = "Field `miscntovf` writer - Overflow bit for Missed Frame Counter"]
pub type MiscntovfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ovffrmcnt` reader - This field indicates the number of frames missed by the application. This counter is incremented each time the MTL asserts the sideband signal mtl_rxoverflow_o. The counter is cleared when this register is read with mci_be_i\\[2\\]
at 1'b1."]
pub type OvffrmcntR = crate::FieldReader<u16>;
#[doc = "Field `ovffrmcnt` writer - This field indicates the number of frames missed by the application. This counter is incremented each time the MTL asserts the sideband signal mtl_rxoverflow_o. The counter is cleared when this register is read with mci_be_i\\[2\\]
at 1'b1."]
pub type OvffrmcntW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `ovfcntovf` reader - Overflow bit for FIFO Overflow Counter"]
pub type OvfcntovfR = crate::BitReader;
#[doc = "Field `ovfcntovf` writer - Overflow bit for FIFO Overflow Counter"]
pub type OvfcntovfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - This field indicates the number of frames missed by the controller because of the Host Receive Buffer being unavailable. This counter is incremented each time the DMA discards an incoming frame. The counter is cleared when this register is read with mci_be_i\\[0\\]
at 1'b1."]
    #[inline(always)]
    pub fn misfrmcnt(&self) -> MisfrmcntR {
        MisfrmcntR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 16 - Overflow bit for Missed Frame Counter"]
    #[inline(always)]
    pub fn miscntovf(&self) -> MiscntovfR {
        MiscntovfR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:27 - This field indicates the number of frames missed by the application. This counter is incremented each time the MTL asserts the sideband signal mtl_rxoverflow_o. The counter is cleared when this register is read with mci_be_i\\[2\\]
at 1'b1."]
    #[inline(always)]
    pub fn ovffrmcnt(&self) -> OvffrmcntR {
        OvffrmcntR::new(((self.bits >> 17) & 0x07ff) as u16)
    }
    #[doc = "Bit 28 - Overflow bit for FIFO Overflow Counter"]
    #[inline(always)]
    pub fn ovfcntovf(&self) -> OvfcntovfR {
        OvfcntovfR::new(((self.bits >> 28) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field indicates the number of frames missed by the controller because of the Host Receive Buffer being unavailable. This counter is incremented each time the DMA discards an incoming frame. The counter is cleared when this register is read with mci_be_i\\[0\\]
at 1'b1."]
    #[inline(always)]
    #[must_use]
    pub fn misfrmcnt(&mut self) -> MisfrmcntW<DmagrpMissedFrameAndBufferOverflowCounterSpec> {
        MisfrmcntW::new(self, 0)
    }
    #[doc = "Bit 16 - Overflow bit for Missed Frame Counter"]
    #[inline(always)]
    #[must_use]
    pub fn miscntovf(&mut self) -> MiscntovfW<DmagrpMissedFrameAndBufferOverflowCounterSpec> {
        MiscntovfW::new(self, 16)
    }
    #[doc = "Bits 17:27 - This field indicates the number of frames missed by the application. This counter is incremented each time the MTL asserts the sideband signal mtl_rxoverflow_o. The counter is cleared when this register is read with mci_be_i\\[2\\]
at 1'b1."]
    #[inline(always)]
    #[must_use]
    pub fn ovffrmcnt(&mut self) -> OvffrmcntW<DmagrpMissedFrameAndBufferOverflowCounterSpec> {
        OvffrmcntW::new(self, 17)
    }
    #[doc = "Bit 28 - Overflow bit for FIFO Overflow Counter"]
    #[inline(always)]
    #[must_use]
    pub fn ovfcntovf(&mut self) -> OvfcntovfW<DmagrpMissedFrameAndBufferOverflowCounterSpec> {
        OvfcntovfW::new(self, 28)
    }
}
#[doc = "The DMA maintains two counters to track the number of frames missed during reception. This register reports the current value of the counter. The counter is used for diagnostic purposes. Bits\\[15:0\\]
indicate missed frames because of the host buffer being unavailable. Bits\\[27:17\\]
indicate missed frames because of buffer overflow conditions (MTL and MAC) and runt frames (good frames of less than 64 bytes) dropped by the MTL.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_missed_frame_and_buffer_overflow_counter::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpMissedFrameAndBufferOverflowCounterSpec;
impl crate::RegisterSpec for DmagrpMissedFrameAndBufferOverflowCounterSpec {
    type Ux = u32;
    const OFFSET: u64 = 4128u64;
}
#[doc = "`read()` method returns [`dmagrp_missed_frame_and_buffer_overflow_counter::R`](R) reader structure"]
impl crate::Readable for DmagrpMissedFrameAndBufferOverflowCounterSpec {}
#[doc = "`reset()` method sets dmagrp_Missed_Frame_And_Buffer_Overflow_Counter to value 0"]
impl crate::Resettable for DmagrpMissedFrameAndBufferOverflowCounterSpec {
    const RESET_VALUE: u32 = 0;
}
