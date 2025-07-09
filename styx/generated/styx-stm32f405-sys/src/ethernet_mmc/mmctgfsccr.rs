// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCTGFSCCR` reader"]
pub type R = crate::R<MmctgfsccrSpec>;
#[doc = "Register `MMCTGFSCCR` writer"]
pub type W = crate::W<MmctgfsccrSpec>;
#[doc = "Field `TGFSCC` reader - TGFSCC"]
pub type TgfsccR = crate::FieldReader<u32>;
#[doc = "Field `TGFSCC` writer - TGFSCC"]
pub type TgfsccW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TGFSCC"]
    #[inline(always)]
    pub fn tgfscc(&self) -> TgfsccR {
        TgfsccR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TGFSCC"]
    #[inline(always)]
    #[must_use]
    pub fn tgfscc(&mut self) -> TgfsccW<MmctgfsccrSpec> {
        TgfsccW::new(self, 0)
    }
}
#[doc = "Ethernet MMC transmitted good frames after a single collision counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctgfsccr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctgfsccrSpec;
impl crate::RegisterSpec for MmctgfsccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`mmctgfsccr::R`](R) reader structure"]
impl crate::Readable for MmctgfsccrSpec {}
#[doc = "`reset()` method sets MMCTGFSCCR to value 0"]
impl crate::Resettable for MmctgfsccrSpec {
    const RESET_VALUE: u32 = 0;
}
