// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMAOMR` reader"]
pub type R = crate::R<DmaomrSpec>;
#[doc = "Register `DMAOMR` writer"]
pub type W = crate::W<DmaomrSpec>;
#[doc = "Field `SR` reader - SR"]
pub type SrR = crate::BitReader;
#[doc = "Field `SR` writer - SR"]
pub type SrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OSF` reader - OSF"]
pub type OsfR = crate::BitReader;
#[doc = "Field `OSF` writer - OSF"]
pub type OsfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RTC` reader - RTC"]
pub type RtcR = crate::FieldReader;
#[doc = "Field `RTC` writer - RTC"]
pub type RtcW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FUGF` reader - FUGF"]
pub type FugfR = crate::BitReader;
#[doc = "Field `FUGF` writer - FUGF"]
pub type FugfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FEF` reader - FEF"]
pub type FefR = crate::BitReader;
#[doc = "Field `FEF` writer - FEF"]
pub type FefW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ST` reader - ST"]
pub type StR = crate::BitReader;
#[doc = "Field `ST` writer - ST"]
pub type StW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TTC` reader - TTC"]
pub type TtcR = crate::FieldReader;
#[doc = "Field `TTC` writer - TTC"]
pub type TtcW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `FTF` reader - FTF"]
pub type FtfR = crate::BitReader;
#[doc = "Field `FTF` writer - FTF"]
pub type FtfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSF` reader - TSF"]
pub type TsfR = crate::BitReader;
#[doc = "Field `TSF` writer - TSF"]
pub type TsfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DFRF` reader - DFRF"]
pub type DfrfR = crate::BitReader;
#[doc = "Field `DFRF` writer - DFRF"]
pub type DfrfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RSF` reader - RSF"]
pub type RsfR = crate::BitReader;
#[doc = "Field `RSF` writer - RSF"]
pub type RsfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DTCEFD` reader - DTCEFD"]
pub type DtcefdR = crate::BitReader;
#[doc = "Field `DTCEFD` writer - DTCEFD"]
pub type DtcefdW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - SR"]
    #[inline(always)]
    pub fn sr(&self) -> SrR {
        SrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - OSF"]
    #[inline(always)]
    pub fn osf(&self) -> OsfR {
        OsfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:4 - RTC"]
    #[inline(always)]
    pub fn rtc(&self) -> RtcR {
        RtcR::new(((self.bits >> 3) & 3) as u8)
    }
    #[doc = "Bit 6 - FUGF"]
    #[inline(always)]
    pub fn fugf(&self) -> FugfR {
        FugfR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - FEF"]
    #[inline(always)]
    pub fn fef(&self) -> FefR {
        FefR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 13 - ST"]
    #[inline(always)]
    pub fn st(&self) -> StR {
        StR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 14:16 - TTC"]
    #[inline(always)]
    pub fn ttc(&self) -> TtcR {
        TtcR::new(((self.bits >> 14) & 7) as u8)
    }
    #[doc = "Bit 20 - FTF"]
    #[inline(always)]
    pub fn ftf(&self) -> FtfR {
        FtfR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - TSF"]
    #[inline(always)]
    pub fn tsf(&self) -> TsfR {
        TsfR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 24 - DFRF"]
    #[inline(always)]
    pub fn dfrf(&self) -> DfrfR {
        DfrfR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - RSF"]
    #[inline(always)]
    pub fn rsf(&self) -> RsfR {
        RsfR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - DTCEFD"]
    #[inline(always)]
    pub fn dtcefd(&self) -> DtcefdR {
        DtcefdR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - SR"]
    #[inline(always)]
    #[must_use]
    pub fn sr(&mut self) -> SrW<DmaomrSpec> {
        SrW::new(self, 1)
    }
    #[doc = "Bit 2 - OSF"]
    #[inline(always)]
    #[must_use]
    pub fn osf(&mut self) -> OsfW<DmaomrSpec> {
        OsfW::new(self, 2)
    }
    #[doc = "Bits 3:4 - RTC"]
    #[inline(always)]
    #[must_use]
    pub fn rtc(&mut self) -> RtcW<DmaomrSpec> {
        RtcW::new(self, 3)
    }
    #[doc = "Bit 6 - FUGF"]
    #[inline(always)]
    #[must_use]
    pub fn fugf(&mut self) -> FugfW<DmaomrSpec> {
        FugfW::new(self, 6)
    }
    #[doc = "Bit 7 - FEF"]
    #[inline(always)]
    #[must_use]
    pub fn fef(&mut self) -> FefW<DmaomrSpec> {
        FefW::new(self, 7)
    }
    #[doc = "Bit 13 - ST"]
    #[inline(always)]
    #[must_use]
    pub fn st(&mut self) -> StW<DmaomrSpec> {
        StW::new(self, 13)
    }
    #[doc = "Bits 14:16 - TTC"]
    #[inline(always)]
    #[must_use]
    pub fn ttc(&mut self) -> TtcW<DmaomrSpec> {
        TtcW::new(self, 14)
    }
    #[doc = "Bit 20 - FTF"]
    #[inline(always)]
    #[must_use]
    pub fn ftf(&mut self) -> FtfW<DmaomrSpec> {
        FtfW::new(self, 20)
    }
    #[doc = "Bit 21 - TSF"]
    #[inline(always)]
    #[must_use]
    pub fn tsf(&mut self) -> TsfW<DmaomrSpec> {
        TsfW::new(self, 21)
    }
    #[doc = "Bit 24 - DFRF"]
    #[inline(always)]
    #[must_use]
    pub fn dfrf(&mut self) -> DfrfW<DmaomrSpec> {
        DfrfW::new(self, 24)
    }
    #[doc = "Bit 25 - RSF"]
    #[inline(always)]
    #[must_use]
    pub fn rsf(&mut self) -> RsfW<DmaomrSpec> {
        RsfW::new(self, 25)
    }
    #[doc = "Bit 26 - DTCEFD"]
    #[inline(always)]
    #[must_use]
    pub fn dtcefd(&mut self) -> DtcefdW<DmaomrSpec> {
        DtcefdW::new(self, 26)
    }
}
#[doc = "Ethernet DMA operation mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmaomr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmaomr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaomrSpec;
impl crate::RegisterSpec for DmaomrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`dmaomr::R`](R) reader structure"]
impl crate::Readable for DmaomrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmaomr::W`](W) writer structure"]
impl crate::Writable for DmaomrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMAOMR to value 0"]
impl crate::Resettable for DmaomrSpec {
    const RESET_VALUE: u32 = 0;
}
