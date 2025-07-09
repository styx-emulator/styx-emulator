// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `tbbcnt` reader"]
pub type R = crate::R<TbbcntSpec>;
#[doc = "Register `tbbcnt` writer"]
pub type W = crate::W<TbbcntSpec>;
#[doc = "Field `trans_fifo_byte_count` reader - Number of bytes transferred between Host/DMA memory and BIU FIFO. In 32-bit AMBA data-bus-width modes, register should be accessed in full to avoid read-coherency problems. Both TCBCNT and TBBCNT share same coherency register."]
pub type TransFifoByteCountR = crate::FieldReader<u32>;
#[doc = "Field `trans_fifo_byte_count` writer - Number of bytes transferred between Host/DMA memory and BIU FIFO. In 32-bit AMBA data-bus-width modes, register should be accessed in full to avoid read-coherency problems. Both TCBCNT and TBBCNT share same coherency register."]
pub type TransFifoByteCountW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes transferred between Host/DMA memory and BIU FIFO. In 32-bit AMBA data-bus-width modes, register should be accessed in full to avoid read-coherency problems. Both TCBCNT and TBBCNT share same coherency register."]
    #[inline(always)]
    pub fn trans_fifo_byte_count(&self) -> TransFifoByteCountR {
        TransFifoByteCountR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes transferred between Host/DMA memory and BIU FIFO. In 32-bit AMBA data-bus-width modes, register should be accessed in full to avoid read-coherency problems. Both TCBCNT and TBBCNT share same coherency register."]
    #[inline(always)]
    #[must_use]
    pub fn trans_fifo_byte_count(&mut self) -> TransFifoByteCountW<TbbcntSpec> {
        TransFifoByteCountW::new(self, 0)
    }
}
#[doc = "Tracks number of bytes transferred between Host and FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tbbcnt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TbbcntSpec;
impl crate::RegisterSpec for TbbcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`tbbcnt::R`](R) reader structure"]
impl crate::Readable for TbbcntSpec {}
#[doc = "`reset()` method sets tbbcnt to value 0"]
impl crate::Resettable for TbbcntSpec {
    const RESET_VALUE: u32 = 0;
}
