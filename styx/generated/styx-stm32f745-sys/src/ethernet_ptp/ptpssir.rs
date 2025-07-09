// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPSSIR` reader"]
pub type R = crate::R<PtpssirSpec>;
#[doc = "Register `PTPSSIR` writer"]
pub type W = crate::W<PtpssirSpec>;
#[doc = "Field `STSSI` reader - STSSI"]
pub type StssiR = crate::FieldReader;
#[doc = "Field `STSSI` writer - STSSI"]
pub type StssiW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - STSSI"]
    #[inline(always)]
    pub fn stssi(&self) -> StssiR {
        StssiR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - STSSI"]
    #[inline(always)]
    #[must_use]
    pub fn stssi(&mut self) -> StssiW<PtpssirSpec> {
        StssiW::new(self, 0)
    }
}
#[doc = "Ethernet PTP subsecond increment register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptpssir::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptpssir::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtpssirSpec;
impl crate::RegisterSpec for PtpssirSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ptpssir::R`](R) reader structure"]
impl crate::Readable for PtpssirSpec {}
#[doc = "`write(|w| ..)` method takes [`ptpssir::W`](W) writer structure"]
impl crate::Writable for PtpssirSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPSSIR to value 0"]
impl crate::Resettable for PtpssirSpec {
    const RESET_VALUE: u32 = 0;
}
