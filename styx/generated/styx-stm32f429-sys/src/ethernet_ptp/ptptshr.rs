// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTSHR` reader"]
pub type R = crate::R<PtptshrSpec>;
#[doc = "Register `PTPTSHR` writer"]
pub type W = crate::W<PtptshrSpec>;
#[doc = "Field `STS` reader - STS"]
pub type StsR = crate::FieldReader<u32>;
#[doc = "Field `STS` writer - STS"]
pub type StsW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - STS"]
    #[inline(always)]
    pub fn sts(&self) -> StsR {
        StsR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - STS"]
    #[inline(always)]
    #[must_use]
    pub fn sts(&mut self) -> StsW<PtptshrSpec> {
        StsW::new(self, 0)
    }
}
#[doc = "Ethernet PTP time stamp high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptshr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptshrSpec;
impl crate::RegisterSpec for PtptshrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ptptshr::R`](R) reader structure"]
impl crate::Readable for PtptshrSpec {}
#[doc = "`reset()` method sets PTPTSHR to value 0"]
impl crate::Resettable for PtptshrSpec {
    const RESET_VALUE: u32 = 0;
}
