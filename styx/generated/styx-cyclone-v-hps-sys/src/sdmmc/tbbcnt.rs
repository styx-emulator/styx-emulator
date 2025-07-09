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
