// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DTXFSTS0` reader"]
pub type R = crate::R<OtgHsDtxfsts0Spec>;
#[doc = "Register `OTG_HS_DTXFSTS0` writer"]
pub type W = crate::W<OtgHsDtxfsts0Spec>;
#[doc = "Field `INEPTFSAV` reader - IN endpoint TxFIFO space avail"]
pub type IneptfsavR = crate::FieldReader<u16>;
#[doc = "Field `INEPTFSAV` writer - IN endpoint TxFIFO space avail"]
pub type IneptfsavW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN endpoint TxFIFO space avail"]
    #[inline(always)]
    pub fn ineptfsav(&self) -> IneptfsavR {
        IneptfsavR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN endpoint TxFIFO space avail"]
    #[inline(always)]
    #[must_use]
    pub fn ineptfsav(&mut self) -> IneptfsavW<OtgHsDtxfsts0Spec> {
        IneptfsavW::new(self, 0)
    }
}
#[doc = "OTG_HS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dtxfsts0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDtxfsts0Spec;
impl crate::RegisterSpec for OtgHsDtxfsts0Spec {
    type Ux = u32;
    const OFFSET: u64 = 280u64;
}
#[doc = "`read()` method returns [`otg_hs_dtxfsts0::R`](R) reader structure"]
impl crate::Readable for OtgHsDtxfsts0Spec {}
#[doc = "`reset()` method sets OTG_HS_DTXFSTS0 to value 0"]
impl crate::Resettable for OtgHsDtxfsts0Spec {
    const RESET_VALUE: u32 = 0;
}
