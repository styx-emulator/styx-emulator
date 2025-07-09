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
#[doc = "Register `dmagrp_AHB_or_AXI_Status` reader"]
pub type R = crate::R<DmagrpAhbOrAxiStatusSpec>;
#[doc = "Register `dmagrp_AHB_or_AXI_Status` writer"]
pub type W = crate::W<DmagrpAhbOrAxiStatusSpec>;
#[doc = "Field `axwhsts` reader - When high, it indicates that AXI Master's write channel is active and transferring data"]
pub type AxwhstsR = crate::BitReader;
#[doc = "Field `axwhsts` writer - When high, it indicates that AXI Master's write channel is active and transferring data"]
pub type AxwhstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `axirdsts` reader - When high, it indicates that AXI Master's read channel is active and transferring data."]
pub type AxirdstsR = crate::BitReader;
#[doc = "Field `axirdsts` writer - When high, it indicates that AXI Master's read channel is active and transferring data."]
pub type AxirdstsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When high, it indicates that AXI Master's write channel is active and transferring data"]
    #[inline(always)]
    pub fn axwhsts(&self) -> AxwhstsR {
        AxwhstsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When high, it indicates that AXI Master's read channel is active and transferring data."]
    #[inline(always)]
    pub fn axirdsts(&self) -> AxirdstsR {
        AxirdstsR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When high, it indicates that AXI Master's write channel is active and transferring data"]
    #[inline(always)]
    #[must_use]
    pub fn axwhsts(&mut self) -> AxwhstsW<DmagrpAhbOrAxiStatusSpec> {
        AxwhstsW::new(self, 0)
    }
    #[doc = "Bit 1 - When high, it indicates that AXI Master's read channel is active and transferring data."]
    #[inline(always)]
    #[must_use]
    pub fn axirdsts(&mut self) -> AxirdstsW<DmagrpAhbOrAxiStatusSpec> {
        AxirdstsW::new(self, 1)
    }
}
#[doc = "This register provides the active status of the AXI interface's read and write channels. This register is useful for debugging purposes. In addition, this register is valid only in the Channel 0 DMA when multiple channels are present in the AV mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_ahb_or_axi_status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpAhbOrAxiStatusSpec;
impl crate::RegisterSpec for DmagrpAhbOrAxiStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 4140u64;
}
#[doc = "`read()` method returns [`dmagrp_ahb_or_axi_status::R`](R) reader structure"]
impl crate::Readable for DmagrpAhbOrAxiStatusSpec {}
#[doc = "`reset()` method sets dmagrp_AHB_or_AXI_Status to value 0"]
impl crate::Resettable for DmagrpAhbOrAxiStatusSpec {
    const RESET_VALUE: u32 = 0;
}
