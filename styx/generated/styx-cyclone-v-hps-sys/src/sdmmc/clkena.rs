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
#[doc = "Register `clkena` reader"]
pub type R = crate::R<ClkenaSpec>;
#[doc = "Register `clkena` writer"]
pub type W = crate::W<ClkenaSpec>;
#[doc = "Enables sdmmc_cclk_out.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CclkEnable {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<CclkEnable> for bool {
    #[inline(always)]
    fn from(variant: CclkEnable) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cclk_enable` reader - Enables sdmmc_cclk_out."]
pub type CclkEnableR = crate::BitReader<CclkEnable>;
impl CclkEnableR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CclkEnable {
        match self.bits {
            false => CclkEnable::Disabled,
            true => CclkEnable::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == CclkEnable::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == CclkEnable::Enabled
    }
}
#[doc = "Field `cclk_enable` writer - Enables sdmmc_cclk_out."]
pub type CclkEnableW<'a, REG> = crate::BitWriter<'a, REG, CclkEnable>;
impl<'a, REG> CclkEnableW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(CclkEnable::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(CclkEnable::Enabled)
    }
}
#[doc = "In low-power mode, stop sdmmc_cclk_out when card in IDLE (should be normally set to only MMC and SD memory cards; for SDIO cards, if interrupts must be detected, clock should not be stopped).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CclkLowPower {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<CclkLowPower> for bool {
    #[inline(always)]
    fn from(variant: CclkLowPower) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cclk_low_power` reader - In low-power mode, stop sdmmc_cclk_out when card in IDLE (should be normally set to only MMC and SD memory cards; for SDIO cards, if interrupts must be detected, clock should not be stopped)."]
pub type CclkLowPowerR = crate::BitReader<CclkLowPower>;
impl CclkLowPowerR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CclkLowPower {
        match self.bits {
            false => CclkLowPower::Disabled,
            true => CclkLowPower::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == CclkLowPower::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == CclkLowPower::Enabled
    }
}
#[doc = "Field `cclk_low_power` writer - In low-power mode, stop sdmmc_cclk_out when card in IDLE (should be normally set to only MMC and SD memory cards; for SDIO cards, if interrupts must be detected, clock should not be stopped)."]
pub type CclkLowPowerW<'a, REG> = crate::BitWriter<'a, REG, CclkLowPower>;
impl<'a, REG> CclkLowPowerW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(CclkLowPower::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(CclkLowPower::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Enables sdmmc_cclk_out."]
    #[inline(always)]
    pub fn cclk_enable(&self) -> CclkEnableR {
        CclkEnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 16 - In low-power mode, stop sdmmc_cclk_out when card in IDLE (should be normally set to only MMC and SD memory cards; for SDIO cards, if interrupts must be detected, clock should not be stopped)."]
    #[inline(always)]
    pub fn cclk_low_power(&self) -> CclkLowPowerR {
        CclkLowPowerR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables sdmmc_cclk_out."]
    #[inline(always)]
    #[must_use]
    pub fn cclk_enable(&mut self) -> CclkEnableW<ClkenaSpec> {
        CclkEnableW::new(self, 0)
    }
    #[doc = "Bit 16 - In low-power mode, stop sdmmc_cclk_out when card in IDLE (should be normally set to only MMC and SD memory cards; for SDIO cards, if interrupts must be detected, clock should not be stopped)."]
    #[inline(always)]
    #[must_use]
    pub fn cclk_low_power(&mut self) -> CclkLowPowerW<ClkenaSpec> {
        CclkLowPowerW::new(self, 16)
    }
}
#[doc = "Controls external SD/MMC Clock Enable.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clkena::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clkena::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ClkenaSpec;
impl crate::RegisterSpec for ClkenaSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`clkena::R`](R) reader structure"]
impl crate::Readable for ClkenaSpec {}
#[doc = "`write(|w| ..)` method takes [`clkena::W`](W) writer structure"]
impl crate::Writable for ClkenaSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets clkena to value 0"]
impl crate::Resettable for ClkenaSpec {
    const RESET_VALUE: u32 = 0;
}
