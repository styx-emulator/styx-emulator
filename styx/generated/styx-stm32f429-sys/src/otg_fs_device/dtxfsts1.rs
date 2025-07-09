// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DTXFSTS1` reader"]
pub type R = crate::R<Dtxfsts1Spec>;
#[doc = "Register `DTXFSTS1` writer"]
pub type W = crate::W<Dtxfsts1Spec>;
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
    pub fn ineptfsav(&mut self) -> IneptfsavW<Dtxfsts1Spec> {
        IneptfsavW::new(self, 0)
    }
}
#[doc = "OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtxfsts1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dtxfsts1Spec;
impl crate::RegisterSpec for Dtxfsts1Spec {
    type Ux = u32;
    const OFFSET: u64 = 312u64;
}
#[doc = "`read()` method returns [`dtxfsts1::R`](R) reader structure"]
impl crate::Readable for Dtxfsts1Spec {}
#[doc = "`reset()` method sets DTXFSTS1 to value 0"]
impl crate::Resettable for Dtxfsts1Spec {
    const RESET_VALUE: u32 = 0;
}
