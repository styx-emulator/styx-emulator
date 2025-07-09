// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MISR` reader"]
pub type R = crate::R<MisrSpec>;
#[doc = "Register `MISR` writer"]
pub type W = crate::W<MisrSpec>;
#[doc = "Field `INMIS` reader - Input FIFO service masked interrupt status"]
pub type InmisR = crate::BitReader;
#[doc = "Field `INMIS` writer - Input FIFO service masked interrupt status"]
pub type InmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OUTMIS` reader - Output FIFO service masked interrupt status"]
pub type OutmisR = crate::BitReader;
#[doc = "Field `OUTMIS` writer - Output FIFO service masked interrupt status"]
pub type OutmisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Input FIFO service masked interrupt status"]
    #[inline(always)]
    pub fn inmis(&self) -> InmisR {
        InmisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Output FIFO service masked interrupt status"]
    #[inline(always)]
    pub fn outmis(&self) -> OutmisR {
        OutmisR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Input FIFO service masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn inmis(&mut self) -> InmisW<MisrSpec> {
        InmisW::new(self, 0)
    }
    #[doc = "Bit 1 - Output FIFO service masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn outmis(&mut self) -> OutmisW<MisrSpec> {
        OutmisW::new(self, 1)
    }
}
#[doc = "masked interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`misr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MisrSpec;
impl crate::RegisterSpec for MisrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`misr::R`](R) reader structure"]
impl crate::Readable for MisrSpec {}
#[doc = "`reset()` method sets MISR to value 0"]
impl crate::Resettable for MisrSpec {
    const RESET_VALUE: u32 = 0;
}
