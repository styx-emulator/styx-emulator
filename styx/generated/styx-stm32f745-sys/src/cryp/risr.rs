// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RISR` reader"]
pub type R = crate::R<RisrSpec>;
#[doc = "Register `RISR` writer"]
pub type W = crate::W<RisrSpec>;
#[doc = "Field `INRIS` reader - Input FIFO service raw interrupt status"]
pub type InrisR = crate::BitReader;
#[doc = "Field `INRIS` writer - Input FIFO service raw interrupt status"]
pub type InrisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OUTRIS` reader - Output FIFO service raw interrupt status"]
pub type OutrisR = crate::BitReader;
#[doc = "Field `OUTRIS` writer - Output FIFO service raw interrupt status"]
pub type OutrisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Input FIFO service raw interrupt status"]
    #[inline(always)]
    pub fn inris(&self) -> InrisR {
        InrisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Output FIFO service raw interrupt status"]
    #[inline(always)]
    pub fn outris(&self) -> OutrisR {
        OutrisR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Input FIFO service raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn inris(&mut self) -> InrisW<RisrSpec> {
        InrisW::new(self, 0)
    }
    #[doc = "Bit 1 - Output FIFO service raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn outris(&mut self) -> OutrisW<RisrSpec> {
        OutrisW::new(self, 1)
    }
}
#[doc = "raw interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`risr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RisrSpec;
impl crate::RegisterSpec for RisrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`risr::R`](R) reader structure"]
impl crate::Readable for RisrSpec {}
#[doc = "`reset()` method sets RISR to value 0x01"]
impl crate::Resettable for RisrSpec {
    const RESET_VALUE: u32 = 0x01;
}
