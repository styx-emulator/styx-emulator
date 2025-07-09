// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_dtxfsts10` reader"]
pub type R = crate::R<DevgrpDtxfsts10Spec>;
#[doc = "Register `devgrp_dtxfsts10` writer"]
pub type W = crate::W<DevgrpDtxfsts10Spec>;
#[doc = "Field `ineptxfspcavail` reader - Indicates the amount of free space available in the Endpoint TxFIFO. Values are in terms of 32-bit words. 16'h0: Endpoint TxFIFO is full 16'h1: 1 word available 16'h2: 2 words available 16'hn: n words available (where 0 n 32,768) 16'h8000: 32,768 words available Others: Reserved"]
pub type IneptxfspcavailR = crate::FieldReader<u16>;
#[doc = "Field `ineptxfspcavail` writer - Indicates the amount of free space available in the Endpoint TxFIFO. Values are in terms of 32-bit words. 16'h0: Endpoint TxFIFO is full 16'h1: 1 word available 16'h2: 2 words available 16'hn: n words available (where 0 n 32,768) 16'h8000: 32,768 words available Others: Reserved"]
pub type IneptxfspcavailW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Indicates the amount of free space available in the Endpoint TxFIFO. Values are in terms of 32-bit words. 16'h0: Endpoint TxFIFO is full 16'h1: 1 word available 16'h2: 2 words available 16'hn: n words available (where 0 n 32,768) 16'h8000: 32,768 words available Others: Reserved"]
    #[inline(always)]
    pub fn ineptxfspcavail(&self) -> IneptxfspcavailR {
        IneptxfspcavailR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Indicates the amount of free space available in the Endpoint TxFIFO. Values are in terms of 32-bit words. 16'h0: Endpoint TxFIFO is full 16'h1: 1 word available 16'h2: 2 words available 16'hn: n words available (where 0 n 32,768) 16'h8000: 32,768 words available Others: Reserved"]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfspcavail(&mut self) -> IneptxfspcavailW<DevgrpDtxfsts10Spec> {
        IneptxfspcavailW::new(self, 0)
    }
}
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts10::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDtxfsts10Spec;
impl crate::RegisterSpec for DevgrpDtxfsts10Spec {
    type Ux = u32;
    const OFFSET: u64 = 2648u64;
}
#[doc = "`read()` method returns [`devgrp_dtxfsts10::R`](R) reader structure"]
impl crate::Readable for DevgrpDtxfsts10Spec {}
#[doc = "`reset()` method sets devgrp_dtxfsts10 to value 0x2000"]
impl crate::Resettable for DevgrpDtxfsts10Spec {
    const RESET_VALUE: u32 = 0x2000;
}
