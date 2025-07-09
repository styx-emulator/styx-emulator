// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DTXFSTS55` reader"]
pub type R = crate::R<OtgFsDtxfsts55Spec>;
#[doc = "Register `OTG_FS_DTXFSTS55` writer"]
pub type W = crate::W<OtgFsDtxfsts55Spec>;
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
    pub fn ineptfsav(&mut self) -> IneptfsavW<OtgFsDtxfsts55Spec> {
        IneptfsavW::new(self, 0)
    }
}
#[doc = "OTG_FS device IN endpoint transmit FIFO status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dtxfsts55::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dtxfsts55::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDtxfsts55Spec;
impl crate::RegisterSpec for OtgFsDtxfsts55Spec {
    type Ux = u32;
    const OFFSET: u64 = 440u64;
}
#[doc = "`read()` method returns [`otg_fs_dtxfsts55::R`](R) reader structure"]
impl crate::Readable for OtgFsDtxfsts55Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_dtxfsts55::W`](W) writer structure"]
impl crate::Writable for OtgFsDtxfsts55Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DTXFSTS55 to value 0"]
impl crate::Resettable for OtgFsDtxfsts55Spec {
    const RESET_VALUE: u32 = 0;
}
