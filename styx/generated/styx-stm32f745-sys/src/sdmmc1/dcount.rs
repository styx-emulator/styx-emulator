// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DCOUNT` reader"]
pub type R = crate::R<DcountSpec>;
#[doc = "Register `DCOUNT` writer"]
pub type W = crate::W<DcountSpec>;
#[doc = "Field `DATACOUNT` reader - Data count value"]
pub type DatacountR = crate::FieldReader<u32>;
#[doc = "Field `DATACOUNT` writer - Data count value"]
pub type DatacountW<'a, REG> = crate::FieldWriter<'a, REG, 25, u32>;
impl R {
    #[doc = "Bits 0:24 - Data count value"]
    #[inline(always)]
    pub fn datacount(&self) -> DatacountR {
        DatacountR::new(self.bits & 0x01ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:24 - Data count value"]
    #[inline(always)]
    #[must_use]
    pub fn datacount(&mut self) -> DatacountW<DcountSpec> {
        DatacountW::new(self, 0)
    }
}
#[doc = "data counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dcount::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DcountSpec;
impl crate::RegisterSpec for DcountSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`dcount::R`](R) reader structure"]
impl crate::Readable for DcountSpec {}
#[doc = "`reset()` method sets DCOUNT to value 0"]
impl crate::Resettable for DcountSpec {
    const RESET_VALUE: u32 = 0;
}
