// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCTGFCR` reader"]
pub type R = crate::R<MmctgfcrSpec>;
#[doc = "Register `MMCTGFCR` writer"]
pub type W = crate::W<MmctgfcrSpec>;
#[doc = "Field `TGFC` reader - HTL"]
pub type TgfcR = crate::FieldReader<u32>;
#[doc = "Field `TGFC` writer - HTL"]
pub type TgfcW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - HTL"]
    #[inline(always)]
    pub fn tgfc(&self) -> TgfcR {
        TgfcR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - HTL"]
    #[inline(always)]
    #[must_use]
    pub fn tgfc(&mut self) -> TgfcW<MmctgfcrSpec> {
        TgfcW::new(self, 0)
    }
}
#[doc = "Ethernet MMC transmitted good frames counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctgfcr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctgfcrSpec;
impl crate::RegisterSpec for MmctgfcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 104u64;
}
#[doc = "`read()` method returns [`mmctgfcr::R`](R) reader structure"]
impl crate::Readable for MmctgfcrSpec {}
#[doc = "`reset()` method sets MMCTGFCR to value 0"]
impl crate::Resettable for MmctgfcrSpec {
    const RESET_VALUE: u32 = 0;
}
