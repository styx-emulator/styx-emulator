// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DIEPEMPMSK` reader"]
pub type R = crate::R<OtgHsDiepempmskSpec>;
#[doc = "Register `OTG_HS_DIEPEMPMSK` writer"]
pub type W = crate::W<OtgHsDiepempmskSpec>;
#[doc = "Field `INEPTXFEM` reader - IN EP Tx FIFO empty interrupt mask bits"]
pub type IneptxfemR = crate::FieldReader<u16>;
#[doc = "Field `INEPTXFEM` writer - IN EP Tx FIFO empty interrupt mask bits"]
pub type IneptxfemW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN EP Tx FIFO empty interrupt mask bits"]
    #[inline(always)]
    pub fn ineptxfem(&self) -> IneptxfemR {
        IneptxfemR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN EP Tx FIFO empty interrupt mask bits"]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfem(&mut self) -> IneptxfemW<OtgHsDiepempmskSpec> {
        IneptxfemW::new(self, 0)
    }
}
#[doc = "OTG_HS device IN endpoint FIFO empty interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_diepempmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_diepempmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDiepempmskSpec;
impl crate::RegisterSpec for OtgHsDiepempmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`otg_hs_diepempmsk::R`](R) reader structure"]
impl crate::Readable for OtgHsDiepempmskSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_diepempmsk::W`](W) writer structure"]
impl crate::Writable for OtgHsDiepempmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DIEPEMPMSK to value 0"]
impl crate::Resettable for OtgHsDiepempmskSpec {
    const RESET_VALUE: u32 = 0;
}
