// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_HNPTXFSIZ_Host` reader"]
pub type R = crate::R<OtgHsHnptxfsizHostSpec>;
#[doc = "Register `OTG_HS_HNPTXFSIZ_Host` writer"]
pub type W = crate::W<OtgHsHnptxfsizHostSpec>;
#[doc = "Field `NPTXFSA` reader - Nonperiodic transmit RAM start address"]
pub type NptxfsaR = crate::FieldReader<u16>;
#[doc = "Field `NPTXFSA` writer - Nonperiodic transmit RAM start address"]
pub type NptxfsaW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `NPTXFD` reader - Nonperiodic TxFIFO depth"]
pub type NptxfdR = crate::FieldReader<u16>;
#[doc = "Field `NPTXFD` writer - Nonperiodic TxFIFO depth"]
pub type NptxfdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Nonperiodic transmit RAM start address"]
    #[inline(always)]
    pub fn nptxfsa(&self) -> NptxfsaR {
        NptxfsaR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - Nonperiodic TxFIFO depth"]
    #[inline(always)]
    pub fn nptxfd(&self) -> NptxfdR {
        NptxfdR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Nonperiodic transmit RAM start address"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfsa(&mut self) -> NptxfsaW<OtgHsHnptxfsizHostSpec> {
        NptxfsaW::new(self, 0)
    }
    #[doc = "Bits 16:31 - Nonperiodic TxFIFO depth"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfd(&mut self) -> NptxfdW<OtgHsHnptxfsizHostSpec> {
        NptxfdW::new(self, 16)
    }
}
#[doc = "OTG_HS nonperiodic transmit FIFO size register (host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hnptxfsiz_host::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hnptxfsiz_host::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsHnptxfsizHostSpec;
impl crate::RegisterSpec for OtgHsHnptxfsizHostSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`otg_hs_hnptxfsiz_host::R`](R) reader structure"]
impl crate::Readable for OtgHsHnptxfsizHostSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_hnptxfsiz_host::W`](W) writer structure"]
impl crate::Writable for OtgHsHnptxfsizHostSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_HNPTXFSIZ_Host to value 0x0200"]
impl crate::Resettable for OtgHsHnptxfsizHostSpec {
    const RESET_VALUE: u32 = 0x0200;
}
