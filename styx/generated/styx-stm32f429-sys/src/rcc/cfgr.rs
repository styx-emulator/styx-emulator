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
#[doc = "Register `CFGR` reader"]
pub type R = crate::R<CfgrSpec>;
#[doc = "Register `CFGR` writer"]
pub type W = crate::W<CfgrSpec>;
#[doc = "Field `SW0` reader - System clock switch"]
pub type Sw0R = crate::BitReader;
#[doc = "Field `SW0` writer - System clock switch"]
pub type Sw0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SW1` reader - System clock switch"]
pub type Sw1R = crate::BitReader;
#[doc = "Field `SW1` writer - System clock switch"]
pub type Sw1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SWS0` reader - System clock switch status"]
pub type Sws0R = crate::BitReader;
#[doc = "Field `SWS0` writer - System clock switch status"]
pub type Sws0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SWS1` reader - System clock switch status"]
pub type Sws1R = crate::BitReader;
#[doc = "Field `SWS1` writer - System clock switch status"]
pub type Sws1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HPRE` reader - AHB prescaler"]
pub type HpreR = crate::FieldReader;
#[doc = "Field `HPRE` writer - AHB prescaler"]
pub type HpreW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PPRE1` reader - APB Low speed prescaler (APB1)"]
pub type Ppre1R = crate::FieldReader;
#[doc = "Field `PPRE1` writer - APB Low speed prescaler (APB1)"]
pub type Ppre1W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `PPRE2` reader - APB high-speed prescaler (APB2)"]
pub type Ppre2R = crate::FieldReader;
#[doc = "Field `PPRE2` writer - APB high-speed prescaler (APB2)"]
pub type Ppre2W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `RTCPRE` reader - HSE division factor for RTC clock"]
pub type RtcpreR = crate::FieldReader;
#[doc = "Field `RTCPRE` writer - HSE division factor for RTC clock"]
pub type RtcpreW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `MCO1` reader - Microcontroller clock output 1"]
pub type Mco1R = crate::FieldReader;
#[doc = "Field `MCO1` writer - Microcontroller clock output 1"]
pub type Mco1W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2SSRC` reader - I2S clock selection"]
pub type I2ssrcR = crate::BitReader;
#[doc = "Field `I2SSRC` writer - I2S clock selection"]
pub type I2ssrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MCO1PRE` reader - MCO1 prescaler"]
pub type Mco1preR = crate::FieldReader;
#[doc = "Field `MCO1PRE` writer - MCO1 prescaler"]
pub type Mco1preW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `MCO2PRE` reader - MCO2 prescaler"]
pub type Mco2preR = crate::FieldReader;
#[doc = "Field `MCO2PRE` writer - MCO2 prescaler"]
pub type Mco2preW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `MCO2` reader - Microcontroller clock output 2"]
pub type Mco2R = crate::FieldReader;
#[doc = "Field `MCO2` writer - Microcontroller clock output 2"]
pub type Mco2W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - System clock switch"]
    #[inline(always)]
    pub fn sw0(&self) -> Sw0R {
        Sw0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - System clock switch"]
    #[inline(always)]
    pub fn sw1(&self) -> Sw1R {
        Sw1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - System clock switch status"]
    #[inline(always)]
    pub fn sws0(&self) -> Sws0R {
        Sws0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - System clock switch status"]
    #[inline(always)]
    pub fn sws1(&self) -> Sws1R {
        Sws1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:7 - AHB prescaler"]
    #[inline(always)]
    pub fn hpre(&self) -> HpreR {
        HpreR::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 10:12 - APB Low speed prescaler (APB1)"]
    #[inline(always)]
    pub fn ppre1(&self) -> Ppre1R {
        Ppre1R::new(((self.bits >> 10) & 7) as u8)
    }
    #[doc = "Bits 13:15 - APB high-speed prescaler (APB2)"]
    #[inline(always)]
    pub fn ppre2(&self) -> Ppre2R {
        Ppre2R::new(((self.bits >> 13) & 7) as u8)
    }
    #[doc = "Bits 16:20 - HSE division factor for RTC clock"]
    #[inline(always)]
    pub fn rtcpre(&self) -> RtcpreR {
        RtcpreR::new(((self.bits >> 16) & 0x1f) as u8)
    }
    #[doc = "Bits 21:22 - Microcontroller clock output 1"]
    #[inline(always)]
    pub fn mco1(&self) -> Mco1R {
        Mco1R::new(((self.bits >> 21) & 3) as u8)
    }
    #[doc = "Bit 23 - I2S clock selection"]
    #[inline(always)]
    pub fn i2ssrc(&self) -> I2ssrcR {
        I2ssrcR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:26 - MCO1 prescaler"]
    #[inline(always)]
    pub fn mco1pre(&self) -> Mco1preR {
        Mco1preR::new(((self.bits >> 24) & 7) as u8)
    }
    #[doc = "Bits 27:29 - MCO2 prescaler"]
    #[inline(always)]
    pub fn mco2pre(&self) -> Mco2preR {
        Mco2preR::new(((self.bits >> 27) & 7) as u8)
    }
    #[doc = "Bits 30:31 - Microcontroller clock output 2"]
    #[inline(always)]
    pub fn mco2(&self) -> Mco2R {
        Mco2R::new(((self.bits >> 30) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - System clock switch"]
    #[inline(always)]
    #[must_use]
    pub fn sw0(&mut self) -> Sw0W<CfgrSpec> {
        Sw0W::new(self, 0)
    }
    #[doc = "Bit 1 - System clock switch"]
    #[inline(always)]
    #[must_use]
    pub fn sw1(&mut self) -> Sw1W<CfgrSpec> {
        Sw1W::new(self, 1)
    }
    #[doc = "Bit 2 - System clock switch status"]
    #[inline(always)]
    #[must_use]
    pub fn sws0(&mut self) -> Sws0W<CfgrSpec> {
        Sws0W::new(self, 2)
    }
    #[doc = "Bit 3 - System clock switch status"]
    #[inline(always)]
    #[must_use]
    pub fn sws1(&mut self) -> Sws1W<CfgrSpec> {
        Sws1W::new(self, 3)
    }
    #[doc = "Bits 4:7 - AHB prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn hpre(&mut self) -> HpreW<CfgrSpec> {
        HpreW::new(self, 4)
    }
    #[doc = "Bits 10:12 - APB Low speed prescaler (APB1)"]
    #[inline(always)]
    #[must_use]
    pub fn ppre1(&mut self) -> Ppre1W<CfgrSpec> {
        Ppre1W::new(self, 10)
    }
    #[doc = "Bits 13:15 - APB high-speed prescaler (APB2)"]
    #[inline(always)]
    #[must_use]
    pub fn ppre2(&mut self) -> Ppre2W<CfgrSpec> {
        Ppre2W::new(self, 13)
    }
    #[doc = "Bits 16:20 - HSE division factor for RTC clock"]
    #[inline(always)]
    #[must_use]
    pub fn rtcpre(&mut self) -> RtcpreW<CfgrSpec> {
        RtcpreW::new(self, 16)
    }
    #[doc = "Bits 21:22 - Microcontroller clock output 1"]
    #[inline(always)]
    #[must_use]
    pub fn mco1(&mut self) -> Mco1W<CfgrSpec> {
        Mco1W::new(self, 21)
    }
    #[doc = "Bit 23 - I2S clock selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2ssrc(&mut self) -> I2ssrcW<CfgrSpec> {
        I2ssrcW::new(self, 23)
    }
    #[doc = "Bits 24:26 - MCO1 prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn mco1pre(&mut self) -> Mco1preW<CfgrSpec> {
        Mco1preW::new(self, 24)
    }
    #[doc = "Bits 27:29 - MCO2 prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn mco2pre(&mut self) -> Mco2preW<CfgrSpec> {
        Mco2preW::new(self, 27)
    }
    #[doc = "Bits 30:31 - Microcontroller clock output 2"]
    #[inline(always)]
    #[must_use]
    pub fn mco2(&mut self) -> Mco2W<CfgrSpec> {
        Mco2W::new(self, 30)
    }
}
#[doc = "clock configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CfgrSpec;
impl crate::RegisterSpec for CfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`cfgr::R`](R) reader structure"]
impl crate::Readable for CfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`cfgr::W`](W) writer structure"]
impl crate::Writable for CfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CFGR to value 0"]
impl crate::Resettable for CfgrSpec {
    const RESET_VALUE: u32 = 0;
}
