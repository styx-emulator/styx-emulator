// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pwrclkgrp_pcgcctl` reader"]
pub type R = crate::R<PwrclkgrpPcgcctlSpec>;
#[doc = "Register `pwrclkgrp_pcgcctl` writer"]
pub type W = crate::W<PwrclkgrpPcgcctlSpec>;
#[doc = "The application sets this bit to stop the PHY clock (phy_clk) when the USB is suspended, the session is not valid, or the device is disconnected. The application clears this bit when the USB is resumed or a new session starts.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stoppclk {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Stoppclk> for bool {
    #[inline(always)]
    fn from(variant: Stoppclk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stoppclk` reader - The application sets this bit to stop the PHY clock (phy_clk) when the USB is suspended, the session is not valid, or the device is disconnected. The application clears this bit when the USB is resumed or a new session starts."]
pub type StoppclkR = crate::BitReader<Stoppclk>;
impl StoppclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stoppclk {
        match self.bits {
            false => Stoppclk::Disabled,
            true => Stoppclk::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Stoppclk::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Stoppclk::Enabled
    }
}
#[doc = "Field `stoppclk` writer - The application sets this bit to stop the PHY clock (phy_clk) when the USB is suspended, the session is not valid, or the device is disconnected. The application clears this bit when the USB is resumed or a new session starts."]
pub type StoppclkW<'a, REG> = crate::BitWriter<'a, REG, Stoppclk>;
impl<'a, REG> StoppclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Stoppclk::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Stoppclk::Enabled)
    }
}
#[doc = "This bit is valid only in Partial Power-Down mode. Theapplication sets this bit when the power is turned off. The application clears this bit after the power is turned on and the PHY clock is up. The R/W of all core registers are possible only when this bit is set to 1b0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rstpdwnmodule {
    #[doc = "0: `0`"]
    On = 0,
    #[doc = "1: `1`"]
    Off = 1,
}
impl From<Rstpdwnmodule> for bool {
    #[inline(always)]
    fn from(variant: Rstpdwnmodule) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rstpdwnmodule` reader - This bit is valid only in Partial Power-Down mode. Theapplication sets this bit when the power is turned off. The application clears this bit after the power is turned on and the PHY clock is up. The R/W of all core registers are possible only when this bit is set to 1b0."]
pub type RstpdwnmoduleR = crate::BitReader<Rstpdwnmodule>;
impl RstpdwnmoduleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rstpdwnmodule {
        match self.bits {
            false => Rstpdwnmodule::On,
            true => Rstpdwnmodule::Off,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_on(&self) -> bool {
        *self == Rstpdwnmodule::On
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_off(&self) -> bool {
        *self == Rstpdwnmodule::Off
    }
}
#[doc = "Field `rstpdwnmodule` writer - This bit is valid only in Partial Power-Down mode. Theapplication sets this bit when the power is turned off. The application clears this bit after the power is turned on and the PHY clock is up. The R/W of all core registers are possible only when this bit is set to 1b0."]
pub type RstpdwnmoduleW<'a, REG> = crate::BitWriter<'a, REG, Rstpdwnmodule>;
impl<'a, REG> RstpdwnmoduleW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn on(self) -> &'a mut crate::W<REG> {
        self.variant(Rstpdwnmodule::On)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn off(self) -> &'a mut crate::W<REG> {
        self.variant(Rstpdwnmodule::Off)
    }
}
#[doc = "Indicates that the PHY is in Sleep State.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Physleep {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Physleep> for bool {
    #[inline(always)]
    fn from(variant: Physleep) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `physleep` reader - Indicates that the PHY is in Sleep State."]
pub type PhysleepR = crate::BitReader<Physleep>;
impl PhysleepR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Physleep {
        match self.bits {
            false => Physleep::Inactive,
            true => Physleep::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Physleep::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Physleep::Active
    }
}
#[doc = "Field `physleep` writer - Indicates that the PHY is in Sleep State."]
pub type PhysleepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates that the PHY is in deep sleep when in L1 state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L1suspended {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<L1suspended> for bool {
    #[inline(always)]
    fn from(variant: L1suspended) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `l1suspended` reader - Indicates that the PHY is in deep sleep when in L1 state."]
pub type L1suspendedR = crate::BitReader<L1suspended>;
impl L1suspendedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> L1suspended {
        match self.bits {
            false => L1suspended::Inactive,
            true => L1suspended::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == L1suspended::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == L1suspended::Active
    }
}
#[doc = "Field `l1suspended` writer - Indicates that the PHY is in deep sleep when in L1 state."]
pub type L1suspendedW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - The application sets this bit to stop the PHY clock (phy_clk) when the USB is suspended, the session is not valid, or the device is disconnected. The application clears this bit when the USB is resumed or a new session starts."]
    #[inline(always)]
    pub fn stoppclk(&self) -> StoppclkR {
        StoppclkR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is valid only in Partial Power-Down mode. Theapplication sets this bit when the power is turned off. The application clears this bit after the power is turned on and the PHY clock is up. The R/W of all core registers are possible only when this bit is set to 1b0."]
    #[inline(always)]
    pub fn rstpdwnmodule(&self) -> RstpdwnmoduleR {
        RstpdwnmoduleR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 6 - Indicates that the PHY is in Sleep State."]
    #[inline(always)]
    pub fn physleep(&self) -> PhysleepR {
        PhysleepR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Indicates that the PHY is in deep sleep when in L1 state."]
    #[inline(always)]
    pub fn l1suspended(&self) -> L1suspendedR {
        L1suspendedR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - The application sets this bit to stop the PHY clock (phy_clk) when the USB is suspended, the session is not valid, or the device is disconnected. The application clears this bit when the USB is resumed or a new session starts."]
    #[inline(always)]
    #[must_use]
    pub fn stoppclk(&mut self) -> StoppclkW<PwrclkgrpPcgcctlSpec> {
        StoppclkW::new(self, 0)
    }
    #[doc = "Bit 3 - This bit is valid only in Partial Power-Down mode. Theapplication sets this bit when the power is turned off. The application clears this bit after the power is turned on and the PHY clock is up. The R/W of all core registers are possible only when this bit is set to 1b0."]
    #[inline(always)]
    #[must_use]
    pub fn rstpdwnmodule(&mut self) -> RstpdwnmoduleW<PwrclkgrpPcgcctlSpec> {
        RstpdwnmoduleW::new(self, 3)
    }
    #[doc = "Bit 6 - Indicates that the PHY is in Sleep State."]
    #[inline(always)]
    #[must_use]
    pub fn physleep(&mut self) -> PhysleepW<PwrclkgrpPcgcctlSpec> {
        PhysleepW::new(self, 6)
    }
    #[doc = "Bit 7 - Indicates that the PHY is in deep sleep when in L1 state."]
    #[inline(always)]
    #[must_use]
    pub fn l1suspended(&mut self) -> L1suspendedW<PwrclkgrpPcgcctlSpec> {
        L1suspendedW::new(self, 7)
    }
}
#[doc = "This register is available in Host and Device modes. The application can use this register to control the core's power-down and clock gating features. Because the CSR module is turned off during power-down, this register is implemented in the AHB Slave BIU module.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pwrclkgrp_pcgcctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pwrclkgrp_pcgcctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PwrclkgrpPcgcctlSpec;
impl crate::RegisterSpec for PwrclkgrpPcgcctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 3584u64;
}
#[doc = "`read()` method returns [`pwrclkgrp_pcgcctl::R`](R) reader structure"]
impl crate::Readable for PwrclkgrpPcgcctlSpec {}
#[doc = "`write(|w| ..)` method takes [`pwrclkgrp_pcgcctl::W`](W) writer structure"]
impl crate::Writable for PwrclkgrpPcgcctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pwrclkgrp_pcgcctl to value 0"]
impl crate::Resettable for PwrclkgrpPcgcctlSpec {
    const RESET_VALUE: u32 = 0;
}
