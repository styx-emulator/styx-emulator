// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DTXFSTS1` reader"]
pub type R = crate::R<OtgFsDtxfsts1Spec>;
#[doc = "Register `OTG_FS_DTXFSTS1` writer"]
pub type W = crate::W<OtgFsDtxfsts1Spec>;
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
    pub fn ineptfsav(&mut self) -> IneptfsavW<OtgFsDtxfsts1Spec> {
        IneptfsavW::new(self, 0)
    }
}
#[doc = "OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDtxfsts1Spec;
impl crate::RegisterSpec for OtgFsDtxfsts1Spec {
    type Ux = u32;
    const OFFSET: u64 = 312u64;
}
#[doc = "`read()` method returns [`otg_fs_dtxfsts1::R`](R) reader structure"]
impl crate::Readable for OtgFsDtxfsts1Spec {}
#[doc = "`reset()` method sets OTG_FS_DTXFSTS1 to value 0"]
impl crate::Resettable for OtgFsDtxfsts1Spec {
    const RESET_VALUE: u32 = 0;
}
