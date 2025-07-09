// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `BDCR` reader"]
pub type R = crate::R<BdcrSpec>;
#[doc = "Register `BDCR` writer"]
pub type W = crate::W<BdcrSpec>;
#[doc = "Field `LSEON` reader - External low-speed oscillator enable"]
pub type LseonR = crate::BitReader;
#[doc = "Field `LSEON` writer - External low-speed oscillator enable"]
pub type LseonW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSERDY` reader - External low-speed oscillator ready"]
pub type LserdyR = crate::BitReader;
#[doc = "Field `LSERDY` writer - External low-speed oscillator ready"]
pub type LserdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSEBYP` reader - External low-speed oscillator bypass"]
pub type LsebypR = crate::BitReader;
#[doc = "Field `LSEBYP` writer - External low-speed oscillator bypass"]
pub type LsebypW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RTCSEL0` reader - RTC clock source selection"]
pub type Rtcsel0R = crate::BitReader;
#[doc = "Field `RTCSEL0` writer - RTC clock source selection"]
pub type Rtcsel0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RTCSEL1` reader - RTC clock source selection"]
pub type Rtcsel1R = crate::BitReader;
#[doc = "Field `RTCSEL1` writer - RTC clock source selection"]
pub type Rtcsel1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RTCEN` reader - RTC clock enable"]
pub type RtcenR = crate::BitReader;
#[doc = "Field `RTCEN` writer - RTC clock enable"]
pub type RtcenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BDRST` reader - Backup domain software reset"]
pub type BdrstR = crate::BitReader;
#[doc = "Field `BDRST` writer - Backup domain software reset"]
pub type BdrstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - External low-speed oscillator enable"]
    #[inline(always)]
    pub fn lseon(&self) -> LseonR {
        LseonR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - External low-speed oscillator ready"]
    #[inline(always)]
    pub fn lserdy(&self) -> LserdyR {
        LserdyR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - External low-speed oscillator bypass"]
    #[inline(always)]
    pub fn lsebyp(&self) -> LsebypR {
        LsebypR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 8 - RTC clock source selection"]
    #[inline(always)]
    pub fn rtcsel0(&self) -> Rtcsel0R {
        Rtcsel0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - RTC clock source selection"]
    #[inline(always)]
    pub fn rtcsel1(&self) -> Rtcsel1R {
        Rtcsel1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 15 - RTC clock enable"]
    #[inline(always)]
    pub fn rtcen(&self) -> RtcenR {
        RtcenR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Backup domain software reset"]
    #[inline(always)]
    pub fn bdrst(&self) -> BdrstR {
        BdrstR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - External low-speed oscillator enable"]
    #[inline(always)]
    #[must_use]
    pub fn lseon(&mut self) -> LseonW<BdcrSpec> {
        LseonW::new(self, 0)
    }
    #[doc = "Bit 1 - External low-speed oscillator ready"]
    #[inline(always)]
    #[must_use]
    pub fn lserdy(&mut self) -> LserdyW<BdcrSpec> {
        LserdyW::new(self, 1)
    }
    #[doc = "Bit 2 - External low-speed oscillator bypass"]
    #[inline(always)]
    #[must_use]
    pub fn lsebyp(&mut self) -> LsebypW<BdcrSpec> {
        LsebypW::new(self, 2)
    }
    #[doc = "Bit 8 - RTC clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn rtcsel0(&mut self) -> Rtcsel0W<BdcrSpec> {
        Rtcsel0W::new(self, 8)
    }
    #[doc = "Bit 9 - RTC clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn rtcsel1(&mut self) -> Rtcsel1W<BdcrSpec> {
        Rtcsel1W::new(self, 9)
    }
    #[doc = "Bit 15 - RTC clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn rtcen(&mut self) -> RtcenW<BdcrSpec> {
        RtcenW::new(self, 15)
    }
    #[doc = "Bit 16 - Backup domain software reset"]
    #[inline(always)]
    #[must_use]
    pub fn bdrst(&mut self) -> BdrstW<BdcrSpec> {
        BdrstW::new(self, 16)
    }
}
#[doc = "Backup domain control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bdcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bdcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BdcrSpec;
impl crate::RegisterSpec for BdcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`bdcr::R`](R) reader structure"]
impl crate::Readable for BdcrSpec {}
#[doc = "`write(|w| ..)` method takes [`bdcr::W`](W) writer structure"]
impl crate::Writable for BdcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BDCR to value 0"]
impl crate::Resettable for BdcrSpec {
    const RESET_VALUE: u32 = 0;
}
