// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DTXFSTS2` reader"]
pub type R = crate::R<OtgFsDtxfsts2Spec>;
#[doc = "Register `OTG_FS_DTXFSTS2` writer"]
pub type W = crate::W<OtgFsDtxfsts2Spec>;
#[doc = "Field `INEPTFSAV` reader - IN endpoint TxFIFO space available"]
pub type IneptfsavR = crate::FieldReader<u16>;
#[doc = "Field `INEPTFSAV` writer - IN endpoint TxFIFO space available"]
pub type IneptfsavW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN endpoint TxFIFO space available"]
    #[inline(always)]
    pub fn ineptfsav(&self) -> IneptfsavR {
        IneptfsavR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN endpoint TxFIFO space available"]
    #[inline(always)]
    #[must_use]
    pub fn ineptfsav(&mut self) -> IneptfsavW<OtgFsDtxfsts2Spec> {
        IneptfsavW::new(self, 0)
    }
}
#[doc = "OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDtxfsts2Spec;
impl crate::RegisterSpec for OtgFsDtxfsts2Spec {
    type Ux = u32;
    const OFFSET: u64 = 344u64;
}
#[doc = "`read()` method returns [`otg_fs_dtxfsts2::R`](R) reader structure"]
impl crate::Readable for OtgFsDtxfsts2Spec {}
#[doc = "`reset()` method sets OTG_FS_DTXFSTS2 to value 0"]
impl crate::Resettable for OtgFsDtxfsts2Spec {
    const RESET_VALUE: u32 = 0;
}
