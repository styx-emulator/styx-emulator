// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DIEPDMA2` reader"]
pub type R = crate::R<OtgHsDiepdma2Spec>;
#[doc = "Register `OTG_HS_DIEPDMA2` writer"]
pub type W = crate::W<OtgHsDiepdma2Spec>;
#[doc = "Field `DMAADDR` reader - DMA address"]
pub type DmaaddrR = crate::FieldReader<u32>;
#[doc = "Field `DMAADDR` writer - DMA address"]
pub type DmaaddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - DMA address"]
    #[inline(always)]
    pub fn dmaaddr(&self) -> DmaaddrR {
        DmaaddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - DMA address"]
    #[inline(always)]
    #[must_use]
    pub fn dmaaddr(&mut self) -> DmaaddrW<OtgHsDiepdma2Spec> {
        DmaaddrW::new(self, 0)
    }
}
#[doc = "OTG_HS device endpoint-2 DMA address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepdma2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepdma2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDiepdma2Spec;
impl crate::RegisterSpec for OtgHsDiepdma2Spec {
    type Ux = u32;
    const OFFSET: u64 = 308u64;
}
#[doc = "`read()` method returns [`otg_hs_diepdma2::R`](R) reader structure"]
impl crate::Readable for OtgHsDiepdma2Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_diepdma2::W`](W) writer structure"]
impl crate::Writable for OtgHsDiepdma2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DIEPDMA2 to value 0"]
impl crate::Resettable for OtgHsDiepdma2Spec {
    const RESET_VALUE: u32 = 0;
}
