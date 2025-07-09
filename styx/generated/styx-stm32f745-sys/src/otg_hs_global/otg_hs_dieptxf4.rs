// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DIEPTXF4` reader"]
pub type R = crate::R<OtgHsDieptxf4Spec>;
#[doc = "Register `OTG_HS_DIEPTXF4` writer"]
pub type W = crate::W<OtgHsDieptxf4Spec>;
#[doc = "Field `INEPTXSA` reader - IN endpoint FIFOx transmit RAM start address"]
pub type IneptxsaR = crate::FieldReader<u16>;
#[doc = "Field `INEPTXSA` writer - IN endpoint FIFOx transmit RAM start address"]
pub type IneptxsaW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `INEPTXFD` reader - IN endpoint TxFIFO depth"]
pub type IneptxfdR = crate::FieldReader<u16>;
#[doc = "Field `INEPTXFD` writer - IN endpoint TxFIFO depth"]
pub type IneptxfdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN endpoint FIFOx transmit RAM start address"]
    #[inline(always)]
    pub fn ineptxsa(&self) -> IneptxsaR {
        IneptxsaR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - IN endpoint TxFIFO depth"]
    #[inline(always)]
    pub fn ineptxfd(&self) -> IneptxfdR {
        IneptxfdR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN endpoint FIFOx transmit RAM start address"]
    #[inline(always)]
    #[must_use]
    pub fn ineptxsa(&mut self) -> IneptxsaW<OtgHsDieptxf4Spec> {
        IneptxsaW::new(self, 0)
    }
    #[doc = "Bits 16:31 - IN endpoint TxFIFO depth"]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfd(&mut self) -> IneptxfdW<OtgHsDieptxf4Spec> {
        IneptxfdW::new(self, 16)
    }
}
#[doc = "OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDieptxf4Spec;
impl crate::RegisterSpec for OtgHsDieptxf4Spec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`otg_hs_dieptxf4::R`](R) reader structure"]
impl crate::Readable for OtgHsDieptxf4Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_dieptxf4::W`](W) writer structure"]
impl crate::Writable for OtgHsDieptxf4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DIEPTXF4 to value 0x0200_0400"]
impl crate::Resettable for OtgHsDieptxf4Spec {
    const RESET_VALUE: u32 = 0x0200_0400;
}
