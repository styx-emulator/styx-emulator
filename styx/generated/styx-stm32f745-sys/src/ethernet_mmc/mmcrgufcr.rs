// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCRGUFCR` reader"]
pub type R = crate::R<MmcrgufcrSpec>;
#[doc = "Register `MMCRGUFCR` writer"]
pub type W = crate::W<MmcrgufcrSpec>;
#[doc = "Field `RGUFC` reader - RGUFC"]
pub type RgufcR = crate::FieldReader<u32>;
#[doc = "Field `RGUFC` writer - RGUFC"]
pub type RgufcW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RGUFC"]
    #[inline(always)]
    pub fn rgufc(&self) -> RgufcR {
        RgufcR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RGUFC"]
    #[inline(always)]
    #[must_use]
    pub fn rgufc(&mut self) -> RgufcW<MmcrgufcrSpec> {
        RgufcW::new(self, 0)
    }
}
#[doc = "MMC received good unicast frames counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrgufcr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrgufcrSpec;
impl crate::RegisterSpec for MmcrgufcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 196u64;
}
#[doc = "`read()` method returns [`mmcrgufcr::R`](R) reader structure"]
impl crate::Readable for MmcrgufcrSpec {}
#[doc = "`reset()` method sets MMCRGUFCR to value 0"]
impl crate::Resettable for MmcrgufcrSpec {
    const RESET_VALUE: u32 = 0;
}
