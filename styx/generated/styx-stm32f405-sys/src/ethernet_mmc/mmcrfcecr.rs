// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCRFCECR` reader"]
pub type R = crate::R<MmcrfcecrSpec>;
#[doc = "Register `MMCRFCECR` writer"]
pub type W = crate::W<MmcrfcecrSpec>;
#[doc = "Field `RFCFC` reader - RFCFC"]
pub type RfcfcR = crate::FieldReader<u32>;
#[doc = "Field `RFCFC` writer - RFCFC"]
pub type RfcfcW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RFCFC"]
    #[inline(always)]
    pub fn rfcfc(&self) -> RfcfcR {
        RfcfcR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RFCFC"]
    #[inline(always)]
    #[must_use]
    pub fn rfcfc(&mut self) -> RfcfcW<MmcrfcecrSpec> {
        RfcfcW::new(self, 0)
    }
}
#[doc = "Ethernet MMC received frames with CRC error counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrfcecr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrfcecrSpec;
impl crate::RegisterSpec for MmcrfcecrSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`mmcrfcecr::R`](R) reader structure"]
impl crate::Readable for MmcrfcecrSpec {}
#[doc = "`reset()` method sets MMCRFCECR to value 0"]
impl crate::Resettable for MmcrfcecrSpec {
    const RESET_VALUE: u32 = 0;
}
