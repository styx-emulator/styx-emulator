// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTSCR` reader"]
pub type R = crate::R<PtptscrSpec>;
#[doc = "Register `PTPTSCR` writer"]
pub type W = crate::W<PtptscrSpec>;
#[doc = "Field `TSE` reader - TSE"]
pub type TseR = crate::BitReader;
#[doc = "Field `TSE` writer - TSE"]
pub type TseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSFCU` reader - TSFCU"]
pub type TsfcuR = crate::BitReader;
#[doc = "Field `TSFCU` writer - TSFCU"]
pub type TsfcuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSTI` reader - TSSTI"]
pub type TsstiR = crate::BitReader;
#[doc = "Field `TSSTI` writer - TSSTI"]
pub type TsstiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSTU` reader - TSSTU"]
pub type TsstuR = crate::BitReader;
#[doc = "Field `TSSTU` writer - TSSTU"]
pub type TsstuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSITE` reader - TSITE"]
pub type TsiteR = crate::BitReader;
#[doc = "Field `TSITE` writer - TSITE"]
pub type TsiteW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TTSARU` reader - TTSARU"]
pub type TtsaruR = crate::BitReader;
#[doc = "Field `TTSARU` writer - TTSARU"]
pub type TtsaruW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSARFE` reader - TSSARFE"]
pub type TssarfeR = crate::BitReader;
#[doc = "Field `TSSARFE` writer - TSSARFE"]
pub type TssarfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSSR` reader - TSSSR"]
pub type TsssrR = crate::BitReader;
#[doc = "Field `TSSSR` writer - TSSSR"]
pub type TsssrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSPTPPSV2E` reader - TSPTPPSV2E"]
pub type Tsptppsv2eR = crate::BitReader;
#[doc = "Field `TSPTPPSV2E` writer - TSPTPPSV2E"]
pub type Tsptppsv2eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSPTPOEFE` reader - TSSPTPOEFE"]
pub type TssptpoefeR = crate::BitReader;
#[doc = "Field `TSSPTPOEFE` writer - TSSPTPOEFE"]
pub type TssptpoefeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSIPV6FE` reader - TSSIPV6FE"]
pub type Tssipv6feR = crate::BitReader;
#[doc = "Field `TSSIPV6FE` writer - TSSIPV6FE"]
pub type Tssipv6feW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSIPV4FE` reader - TSSIPV4FE"]
pub type Tssipv4feR = crate::BitReader;
#[doc = "Field `TSSIPV4FE` writer - TSSIPV4FE"]
pub type Tssipv4feW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSEME` reader - TSSEME"]
pub type TssemeR = crate::BitReader;
#[doc = "Field `TSSEME` writer - TSSEME"]
pub type TssemeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSSMRME` reader - TSSMRME"]
pub type TssmrmeR = crate::BitReader;
#[doc = "Field `TSSMRME` writer - TSSMRME"]
pub type TssmrmeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSCNT` reader - TSCNT"]
pub type TscntR = crate::FieldReader;
#[doc = "Field `TSCNT` writer - TSCNT"]
pub type TscntW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TSPFFMAE` reader - TSPFFMAE"]
pub type TspffmaeR = crate::BitReader;
#[doc = "Field `TSPFFMAE` writer - TSPFFMAE"]
pub type TspffmaeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TSE"]
    #[inline(always)]
    pub fn tse(&self) -> TseR {
        TseR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TSFCU"]
    #[inline(always)]
    pub fn tsfcu(&self) -> TsfcuR {
        TsfcuR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - TSSTI"]
    #[inline(always)]
    pub fn tssti(&self) -> TsstiR {
        TsstiR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - TSSTU"]
    #[inline(always)]
    pub fn tsstu(&self) -> TsstuR {
        TsstuR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - TSITE"]
    #[inline(always)]
    pub fn tsite(&self) -> TsiteR {
        TsiteR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - TTSARU"]
    #[inline(always)]
    pub fn ttsaru(&self) -> TtsaruR {
        TtsaruR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - TSSARFE"]
    #[inline(always)]
    pub fn tssarfe(&self) -> TssarfeR {
        TssarfeR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - TSSSR"]
    #[inline(always)]
    pub fn tsssr(&self) -> TsssrR {
        TsssrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - TSPTPPSV2E"]
    #[inline(always)]
    pub fn tsptppsv2e(&self) -> Tsptppsv2eR {
        Tsptppsv2eR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - TSSPTPOEFE"]
    #[inline(always)]
    pub fn tssptpoefe(&self) -> TssptpoefeR {
        TssptpoefeR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - TSSIPV6FE"]
    #[inline(always)]
    pub fn tssipv6fe(&self) -> Tssipv6feR {
        Tssipv6feR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - TSSIPV4FE"]
    #[inline(always)]
    pub fn tssipv4fe(&self) -> Tssipv4feR {
        Tssipv4feR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - TSSEME"]
    #[inline(always)]
    pub fn tsseme(&self) -> TssemeR {
        TssemeR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - TSSMRME"]
    #[inline(always)]
    pub fn tssmrme(&self) -> TssmrmeR {
        TssmrmeR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:17 - TSCNT"]
    #[inline(always)]
    pub fn tscnt(&self) -> TscntR {
        TscntR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 18 - TSPFFMAE"]
    #[inline(always)]
    pub fn tspffmae(&self) -> TspffmaeR {
        TspffmaeR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TSE"]
    #[inline(always)]
    #[must_use]
    pub fn tse(&mut self) -> TseW<PtptscrSpec> {
        TseW::new(self, 0)
    }
    #[doc = "Bit 1 - TSFCU"]
    #[inline(always)]
    #[must_use]
    pub fn tsfcu(&mut self) -> TsfcuW<PtptscrSpec> {
        TsfcuW::new(self, 1)
    }
    #[doc = "Bit 2 - TSSTI"]
    #[inline(always)]
    #[must_use]
    pub fn tssti(&mut self) -> TsstiW<PtptscrSpec> {
        TsstiW::new(self, 2)
    }
    #[doc = "Bit 3 - TSSTU"]
    #[inline(always)]
    #[must_use]
    pub fn tsstu(&mut self) -> TsstuW<PtptscrSpec> {
        TsstuW::new(self, 3)
    }
    #[doc = "Bit 4 - TSITE"]
    #[inline(always)]
    #[must_use]
    pub fn tsite(&mut self) -> TsiteW<PtptscrSpec> {
        TsiteW::new(self, 4)
    }
    #[doc = "Bit 5 - TTSARU"]
    #[inline(always)]
    #[must_use]
    pub fn ttsaru(&mut self) -> TtsaruW<PtptscrSpec> {
        TtsaruW::new(self, 5)
    }
    #[doc = "Bit 8 - TSSARFE"]
    #[inline(always)]
    #[must_use]
    pub fn tssarfe(&mut self) -> TssarfeW<PtptscrSpec> {
        TssarfeW::new(self, 8)
    }
    #[doc = "Bit 9 - TSSSR"]
    #[inline(always)]
    #[must_use]
    pub fn tsssr(&mut self) -> TsssrW<PtptscrSpec> {
        TsssrW::new(self, 9)
    }
    #[doc = "Bit 10 - TSPTPPSV2E"]
    #[inline(always)]
    #[must_use]
    pub fn tsptppsv2e(&mut self) -> Tsptppsv2eW<PtptscrSpec> {
        Tsptppsv2eW::new(self, 10)
    }
    #[doc = "Bit 11 - TSSPTPOEFE"]
    #[inline(always)]
    #[must_use]
    pub fn tssptpoefe(&mut self) -> TssptpoefeW<PtptscrSpec> {
        TssptpoefeW::new(self, 11)
    }
    #[doc = "Bit 12 - TSSIPV6FE"]
    #[inline(always)]
    #[must_use]
    pub fn tssipv6fe(&mut self) -> Tssipv6feW<PtptscrSpec> {
        Tssipv6feW::new(self, 12)
    }
    #[doc = "Bit 13 - TSSIPV4FE"]
    #[inline(always)]
    #[must_use]
    pub fn tssipv4fe(&mut self) -> Tssipv4feW<PtptscrSpec> {
        Tssipv4feW::new(self, 13)
    }
    #[doc = "Bit 14 - TSSEME"]
    #[inline(always)]
    #[must_use]
    pub fn tsseme(&mut self) -> TssemeW<PtptscrSpec> {
        TssemeW::new(self, 14)
    }
    #[doc = "Bit 15 - TSSMRME"]
    #[inline(always)]
    #[must_use]
    pub fn tssmrme(&mut self) -> TssmrmeW<PtptscrSpec> {
        TssmrmeW::new(self, 15)
    }
    #[doc = "Bits 16:17 - TSCNT"]
    #[inline(always)]
    #[must_use]
    pub fn tscnt(&mut self) -> TscntW<PtptscrSpec> {
        TscntW::new(self, 16)
    }
    #[doc = "Bit 18 - TSPFFMAE"]
    #[inline(always)]
    #[must_use]
    pub fn tspffmae(&mut self) -> TspffmaeW<PtptscrSpec> {
        TspffmaeW::new(self, 18)
    }
}
#[doc = "Ethernet PTP time stamp control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptscr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptscr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptscrSpec;
impl crate::RegisterSpec for PtptscrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`ptptscr::R`](R) reader structure"]
impl crate::Readable for PtptscrSpec {}
#[doc = "`write(|w| ..)` method takes [`ptptscr::W`](W) writer structure"]
impl crate::Writable for PtptscrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPTSCR to value 0x2000"]
impl crate::Resettable for PtptscrSpec {
    const RESET_VALUE: u32 = 0x2000;
}
