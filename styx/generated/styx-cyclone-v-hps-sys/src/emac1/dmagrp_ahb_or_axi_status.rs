// SPDX-License-Identifier: BSD-2-Clause
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
