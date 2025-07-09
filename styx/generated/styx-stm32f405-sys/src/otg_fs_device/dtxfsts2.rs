// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DTXFSTS2` reader"]
pub type R = crate::R<Dtxfsts2Spec>;
#[doc = "Register `DTXFSTS2` writer"]
pub type W = crate::W<Dtxfsts2Spec>;
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
    pub fn ineptfsav(&mut self) -> IneptfsavW<Dtxfsts2Spec> {
        IneptfsavW::new(self, 0)
    }
}
#[doc = "OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtxfsts2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dtxfsts2Spec;
impl crate::RegisterSpec for Dtxfsts2Spec {
    type Ux = u32;
    const OFFSET: u64 = 344u64;
}
#[doc = "`read()` method returns [`dtxfsts2::R`](R) reader structure"]
impl crate::Readable for Dtxfsts2Spec {}
#[doc = "`reset()` method sets DTXFSTS2 to value 0"]
impl crate::Resettable for Dtxfsts2Spec {
    const RESET_VALUE: u32 = 0;
}
