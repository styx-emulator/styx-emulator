// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCTGFMSCCR` reader"]
pub type R = crate::R<MmctgfmsccrSpec>;
#[doc = "Register `MMCTGFMSCCR` writer"]
pub type W = crate::W<MmctgfmsccrSpec>;
#[doc = "Field `TGFMSCC` reader - TGFMSCC"]
pub type TgfmsccR = crate::FieldReader<u32>;
#[doc = "Field `TGFMSCC` writer - TGFMSCC"]
pub type TgfmsccW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TGFMSCC"]
    #[inline(always)]
    pub fn tgfmscc(&self) -> TgfmsccR {
        TgfmsccR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TGFMSCC"]
    #[inline(always)]
    #[must_use]
    pub fn tgfmscc(&mut self) -> TgfmsccW<MmctgfmsccrSpec> {
        TgfmsccW::new(self, 0)
    }
}
#[doc = "Ethernet MMC transmitted good frames after more than a single collision\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctgfmsccr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctgfmsccrSpec;
impl crate::RegisterSpec for MmctgfmsccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`mmctgfmsccr::R`](R) reader structure"]
impl crate::Readable for MmctgfmsccrSpec {}
#[doc = "`reset()` method sets MMCTGFMSCCR to value 0"]
impl crate::Resettable for MmctgfmsccrSpec {
    const RESET_VALUE: u32 = 0;
}
