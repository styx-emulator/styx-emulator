// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTSLR` reader"]
pub type R = crate::R<PtptslrSpec>;
#[doc = "Register `PTPTSLR` writer"]
pub type W = crate::W<PtptslrSpec>;
#[doc = "Field `STSS` reader - STSS"]
pub type StssR = crate::FieldReader<u32>;
#[doc = "Field `STSS` writer - STSS"]
pub type StssW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
#[doc = "Field `STPNS` reader - STPNS"]
pub type StpnsR = crate::BitReader;
#[doc = "Field `STPNS` writer - STPNS"]
pub type StpnsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:30 - STSS"]
    #[inline(always)]
    pub fn stss(&self) -> StssR {
        StssR::new(self.bits & 0x7fff_ffff)
    }
    #[doc = "Bit 31 - STPNS"]
    #[inline(always)]
    pub fn stpns(&self) -> StpnsR {
        StpnsR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:30 - STSS"]
    #[inline(always)]
    #[must_use]
    pub fn stss(&mut self) -> StssW<PtptslrSpec> {
        StssW::new(self, 0)
    }
    #[doc = "Bit 31 - STPNS"]
    #[inline(always)]
    #[must_use]
    pub fn stpns(&mut self) -> StpnsW<PtptslrSpec> {
        StpnsW::new(self, 31)
    }
}
#[doc = "Ethernet PTP time stamp low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptslr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptslrSpec;
impl crate::RegisterSpec for PtptslrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`ptptslr::R`](R) reader structure"]
impl crate::Readable for PtptslrSpec {}
#[doc = "`reset()` method sets PTPTSLR to value 0"]
impl crate::Resettable for PtptslrSpec {
    const RESET_VALUE: u32 = 0;
}
