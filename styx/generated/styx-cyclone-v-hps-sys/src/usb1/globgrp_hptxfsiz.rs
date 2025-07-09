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
#[doc = "Register `globgrp_hptxfsiz` reader"]
pub type R = crate::R<GlobgrpHptxfsizSpec>;
#[doc = "Register `globgrp_hptxfsiz` writer"]
pub type W = crate::W<GlobgrpHptxfsizSpec>;
#[doc = "Field `ptxfstaddr` reader - The power-on reset value of this register is the sum of the Largest Rx Data FIFO Depth and Largest Non-periodic Tx Data FIFO. Programmed values must not exceed the power-on value"]
pub type PtxfstaddrR = crate::FieldReader<u16>;
#[doc = "Field `ptxfstaddr` writer - The power-on reset value of this register is the sum of the Largest Rx Data FIFO Depth and Largest Non-periodic Tx Data FIFO. Programmed values must not exceed the power-on value"]
pub type PtxfstaddrW<'a, REG> = crate::FieldWriter<'a, REG, 15, u16>;
#[doc = "Field `ptxfsize` reader - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 1024 The power-on reset value of this register is specified as the 1024."]
pub type PtxfsizeR = crate::FieldReader<u16>;
#[doc = "Field `ptxfsize` writer - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 1024 The power-on reset value of this register is specified as the 1024."]
pub type PtxfsizeW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:14 - The power-on reset value of this register is the sum of the Largest Rx Data FIFO Depth and Largest Non-periodic Tx Data FIFO. Programmed values must not exceed the power-on value"]
    #[inline(always)]
    pub fn ptxfstaddr(&self) -> PtxfstaddrR {
        PtxfstaddrR::new((self.bits & 0x7fff) as u16)
    }
    #[doc = "Bits 16:29 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 1024 The power-on reset value of this register is specified as the 1024."]
    #[inline(always)]
    pub fn ptxfsize(&self) -> PtxfsizeR {
        PtxfsizeR::new(((self.bits >> 16) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:14 - The power-on reset value of this register is the sum of the Largest Rx Data FIFO Depth and Largest Non-periodic Tx Data FIFO. Programmed values must not exceed the power-on value"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfstaddr(&mut self) -> PtxfstaddrW<GlobgrpHptxfsizSpec> {
        PtxfstaddrW::new(self, 0)
    }
    #[doc = "Bits 16:29 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 1024 The power-on reset value of this register is specified as the 1024."]
    #[inline(always)]
    #[must_use]
    pub fn ptxfsize(&mut self) -> PtxfsizeW<GlobgrpHptxfsizSpec> {
        PtxfsizeW::new(self, 16)
    }
}
#[doc = "This register holds the size and the memory start address of the Periodic TxFIFO\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_hptxfsiz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_hptxfsiz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpHptxfsizSpec;
impl crate::RegisterSpec for GlobgrpHptxfsizSpec {
    type Ux = u32;
    const OFFSET: u64 = 256u64;
}
#[doc = "`read()` method returns [`globgrp_hptxfsiz::R`](R) reader structure"]
impl crate::Readable for GlobgrpHptxfsizSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_hptxfsiz::W`](W) writer structure"]
impl crate::Writable for GlobgrpHptxfsizSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_hptxfsiz to value 0x2000_4000"]
impl crate::Resettable for GlobgrpHptxfsizSpec {
    const RESET_VALUE: u32 = 0x2000_4000;
}
