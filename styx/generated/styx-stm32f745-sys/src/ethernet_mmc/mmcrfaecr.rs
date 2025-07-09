// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCRFAECR` reader"]
pub type R = crate::R<MmcrfaecrSpec>;
#[doc = "Register `MMCRFAECR` writer"]
pub type W = crate::W<MmcrfaecrSpec>;
#[doc = "Field `RFAEC` reader - RFAEC"]
pub type RfaecR = crate::FieldReader<u32>;
#[doc = "Field `RFAEC` writer - RFAEC"]
pub type RfaecW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RFAEC"]
    #[inline(always)]
    pub fn rfaec(&self) -> RfaecR {
        RfaecR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RFAEC"]
    #[inline(always)]
    #[must_use]
    pub fn rfaec(&mut self) -> RfaecW<MmcrfaecrSpec> {
        RfaecW::new(self, 0)
    }
}
#[doc = "Ethernet MMC received frames with alignment error counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrfaecr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrfaecrSpec;
impl crate::RegisterSpec for MmcrfaecrSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`mmcrfaecr::R`](R) reader structure"]
impl crate::Readable for MmcrfaecrSpec {}
#[doc = "`reset()` method sets MMCRFAECR to value 0"]
impl crate::Resettable for MmcrfaecrSpec {
    const RESET_VALUE: u32 = 0;
}
