// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `TEF` reader - Transfer error flag"]
pub type TefR = crate::BitReader;
#[doc = "Field `TEF` writer - Transfer error flag"]
pub type TefW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCF` reader - Transfer complete flag"]
pub type TcfR = crate::BitReader;
#[doc = "Field `TCF` writer - Transfer complete flag"]
pub type TcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FTF` reader - FIFO threshold flag"]
pub type FtfR = crate::BitReader;
#[doc = "Field `FTF` writer - FIFO threshold flag"]
pub type FtfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMF` reader - Status match flag"]
pub type SmfR = crate::BitReader;
#[doc = "Field `SMF` writer - Status match flag"]
pub type SmfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TOF` reader - Timeout flag"]
pub type TofR = crate::BitReader;
#[doc = "Field `TOF` writer - Timeout flag"]
pub type TofW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSY` reader - Busy"]
pub type BusyR = crate::BitReader;
#[doc = "Field `BUSY` writer - Busy"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FLEVEL` reader - FIFO level"]
pub type FlevelR = crate::FieldReader;
#[doc = "Field `FLEVEL` writer - FIFO level"]
pub type FlevelW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bit 0 - Transfer error flag"]
    #[inline(always)]
    pub fn tef(&self) -> TefR {
        TefR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Transfer complete flag"]
    #[inline(always)]
    pub fn tcf(&self) -> TcfR {
        TcfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - FIFO threshold flag"]
    #[inline(always)]
    pub fn ftf(&self) -> FtfR {
        FtfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Status match flag"]
    #[inline(always)]
    pub fn smf(&self) -> SmfR {
        SmfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Timeout flag"]
    #[inline(always)]
    pub fn tof(&self) -> TofR {
        TofR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Busy"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 8:14 - FIFO level"]
    #[inline(always)]
    pub fn flevel(&self) -> FlevelR {
        FlevelR::new(((self.bits >> 8) & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer error flag"]
    #[inline(always)]
    #[must_use]
    pub fn tef(&mut self) -> TefW<SrSpec> {
        TefW::new(self, 0)
    }
    #[doc = "Bit 1 - Transfer complete flag"]
    #[inline(always)]
    #[must_use]
    pub fn tcf(&mut self) -> TcfW<SrSpec> {
        TcfW::new(self, 1)
    }
    #[doc = "Bit 2 - FIFO threshold flag"]
    #[inline(always)]
    #[must_use]
    pub fn ftf(&mut self) -> FtfW<SrSpec> {
        FtfW::new(self, 2)
    }
    #[doc = "Bit 3 - Status match flag"]
    #[inline(always)]
    #[must_use]
    pub fn smf(&mut self) -> SmfW<SrSpec> {
        SmfW::new(self, 3)
    }
    #[doc = "Bit 4 - Timeout flag"]
    #[inline(always)]
    #[must_use]
    pub fn tof(&mut self) -> TofW<SrSpec> {
        TofW::new(self, 4)
    }
    #[doc = "Bit 5 - Busy"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<SrSpec> {
        BusyW::new(self, 5)
    }
    #[doc = "Bits 8:14 - FIFO level"]
    #[inline(always)]
    #[must_use]
    pub fn flevel(&mut self) -> FlevelW<SrSpec> {
        FlevelW::new(self, 8)
    }
}
#[doc = "status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
