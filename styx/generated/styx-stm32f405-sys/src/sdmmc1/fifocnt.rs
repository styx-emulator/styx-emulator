// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FIFOCNT` reader"]
pub type R = crate::R<FifocntSpec>;
#[doc = "Register `FIFOCNT` writer"]
pub type W = crate::W<FifocntSpec>;
#[doc = "Field `FIFOCOUNT` reader - Remaining number of words to be written to or read from the FIFO"]
pub type FifocountR = crate::FieldReader<u32>;
#[doc = "Field `FIFOCOUNT` writer - Remaining number of words to be written to or read from the FIFO"]
pub type FifocountW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - Remaining number of words to be written to or read from the FIFO"]
    #[inline(always)]
    pub fn fifocount(&self) -> FifocountR {
        FifocountR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - Remaining number of words to be written to or read from the FIFO"]
    #[inline(always)]
    #[must_use]
    pub fn fifocount(&mut self) -> FifocountW<FifocntSpec> {
        FifocountW::new(self, 0)
    }
}
#[doc = "FIFO counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifocnt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifocntSpec;
impl crate::RegisterSpec for FifocntSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`fifocnt::R`](R) reader structure"]
impl crate::Readable for FifocntSpec {}
#[doc = "`reset()` method sets FIFOCNT to value 0"]
impl crate::Resettable for FifocntSpec {
    const RESET_VALUE: u32 = 0;
}
