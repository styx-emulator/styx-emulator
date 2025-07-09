// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `IFEM` reader - Input FIFO empty"]
pub type IfemR = crate::BitReader;
#[doc = "Field `IFEM` writer - Input FIFO empty"]
pub type IfemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IFNF` reader - Input FIFO not full"]
pub type IfnfR = crate::BitReader;
#[doc = "Field `IFNF` writer - Input FIFO not full"]
pub type IfnfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OFNE` reader - Output FIFO not empty"]
pub type OfneR = crate::BitReader;
#[doc = "Field `OFNE` writer - Output FIFO not empty"]
pub type OfneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OFFU` reader - Output FIFO full"]
pub type OffuR = crate::BitReader;
#[doc = "Field `OFFU` writer - Output FIFO full"]
pub type OffuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSY` reader - Busy bit"]
pub type BusyR = crate::BitReader;
#[doc = "Field `BUSY` writer - Busy bit"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Input FIFO empty"]
    #[inline(always)]
    pub fn ifem(&self) -> IfemR {
        IfemR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Input FIFO not full"]
    #[inline(always)]
    pub fn ifnf(&self) -> IfnfR {
        IfnfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Output FIFO not empty"]
    #[inline(always)]
    pub fn ofne(&self) -> OfneR {
        OfneR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Output FIFO full"]
    #[inline(always)]
    pub fn offu(&self) -> OffuR {
        OffuR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Busy bit"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Input FIFO empty"]
    #[inline(always)]
    #[must_use]
    pub fn ifem(&mut self) -> IfemW<SrSpec> {
        IfemW::new(self, 0)
    }
    #[doc = "Bit 1 - Input FIFO not full"]
    #[inline(always)]
    #[must_use]
    pub fn ifnf(&mut self) -> IfnfW<SrSpec> {
        IfnfW::new(self, 1)
    }
    #[doc = "Bit 2 - Output FIFO not empty"]
    #[inline(always)]
    #[must_use]
    pub fn ofne(&mut self) -> OfneW<SrSpec> {
        OfneW::new(self, 2)
    }
    #[doc = "Bit 3 - Output FIFO full"]
    #[inline(always)]
    #[must_use]
    pub fn offu(&mut self) -> OffuW<SrSpec> {
        OffuW::new(self, 3)
    }
    #[doc = "Bit 4 - Busy bit"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<SrSpec> {
        BusyW::new(self, 4)
    }
}
#[doc = "status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`reset()` method sets SR to value 0x03"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0x03;
}
