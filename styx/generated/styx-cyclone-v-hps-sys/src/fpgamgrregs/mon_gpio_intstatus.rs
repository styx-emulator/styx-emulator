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
#[doc = "Register `mon_gpio_intstatus` reader"]
pub type R = crate::R<MonGpioIntstatusSpec>;
#[doc = "Register `mon_gpio_intstatus` writer"]
pub type W = crate::W<MonGpioIntstatusSpec>;
#[doc = "Indicates whether nSTATUS has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ns {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ns> for bool {
    #[inline(always)]
    fn from(variant: Ns) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ns` reader - Indicates whether nSTATUS has an active interrupt or not (after masking)."]
pub type NsR = crate::BitReader<Ns>;
impl NsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ns {
        match self.bits {
            false => Ns::Inactive,
            true => Ns::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ns::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ns::Active
    }
}
#[doc = "Field `ns` writer - Indicates whether nSTATUS has an active interrupt or not (after masking)."]
pub type NsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether CONF_DONE has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Indicates whether CONF_DONE has an active interrupt or not (after masking)."]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Inactive,
            true => Cd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Cd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Cd::Active
    }
}
#[doc = "Field `cd` writer - Indicates whether CONF_DONE has an active interrupt or not (after masking)."]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether INIT_DONE has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Id> for bool {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `id` reader - Indicates whether INIT_DONE has an active interrupt or not (after masking)."]
pub type IdR = crate::BitReader<Id>;
impl IdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Id {
        match self.bits {
            false => Id::Inactive,
            true => Id::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Id::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Id::Active
    }
}
#[doc = "Field `id` writer - Indicates whether INIT_DONE has an active interrupt or not (after masking)."]
pub type IdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether CRC_ERROR has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crc {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Crc> for bool {
    #[inline(always)]
    fn from(variant: Crc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `crc` reader - Indicates whether CRC_ERROR has an active interrupt or not (after masking)."]
pub type CrcR = crate::BitReader<Crc>;
impl CrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Crc {
        match self.bits {
            false => Crc::Inactive,
            true => Crc::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Crc::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Crc::Active
    }
}
#[doc = "Field `crc` writer - Indicates whether CRC_ERROR has an active interrupt or not (after masking)."]
pub type CrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether CVP_CONF_DONE has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ccd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ccd> for bool {
    #[inline(always)]
    fn from(variant: Ccd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ccd` reader - Indicates whether CVP_CONF_DONE has an active interrupt or not (after masking)."]
pub type CcdR = crate::BitReader<Ccd>;
impl CcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ccd {
        match self.bits {
            false => Ccd::Inactive,
            true => Ccd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ccd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ccd::Active
    }
}
#[doc = "Field `ccd` writer - Indicates whether CVP_CONF_DONE has an active interrupt or not (after masking)."]
pub type CcdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether PR_READY has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prr> for bool {
    #[inline(always)]
    fn from(variant: Prr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prr` reader - Indicates whether PR_READY has an active interrupt or not (after masking)."]
pub type PrrR = crate::BitReader<Prr>;
impl PrrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prr {
        match self.bits {
            false => Prr::Inactive,
            true => Prr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prr::Active
    }
}
#[doc = "Field `prr` writer - Indicates whether PR_READY has an active interrupt or not (after masking)."]
pub type PrrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether PR_ERROR has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pre {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Pre> for bool {
    #[inline(always)]
    fn from(variant: Pre) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pre` reader - Indicates whether PR_ERROR has an active interrupt or not (after masking)."]
pub type PreR = crate::BitReader<Pre>;
impl PreR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pre {
        match self.bits {
            false => Pre::Inactive,
            true => Pre::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Pre::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Pre::Active
    }
}
#[doc = "Field `pre` writer - Indicates whether PR_ERROR has an active interrupt or not (after masking)."]
pub type PreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether PR_DONE has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prd> for bool {
    #[inline(always)]
    fn from(variant: Prd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prd` reader - Indicates whether PR_DONE has an active interrupt or not (after masking)."]
pub type PrdR = crate::BitReader<Prd>;
impl PrdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prd {
        match self.bits {
            false => Prd::Inactive,
            true => Prd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prd::Active
    }
}
#[doc = "Field `prd` writer - Indicates whether PR_DONE has an active interrupt or not (after masking)."]
pub type PrdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether nCONFIG Pin has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ncp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ncp> for bool {
    #[inline(always)]
    fn from(variant: Ncp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ncp` reader - Indicates whether nCONFIG Pin has an active interrupt or not (after masking)."]
pub type NcpR = crate::BitReader<Ncp>;
impl NcpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ncp {
        match self.bits {
            false => Ncp::Inactive,
            true => Ncp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ncp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ncp::Active
    }
}
#[doc = "Field `ncp` writer - Indicates whether nCONFIG Pin has an active interrupt or not (after masking)."]
pub type NcpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether nSTATUS Pin has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nsp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Nsp> for bool {
    #[inline(always)]
    fn from(variant: Nsp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nsp` reader - Indicates whether nSTATUS Pin has an active interrupt or not (after masking)."]
pub type NspR = crate::BitReader<Nsp>;
impl NspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nsp {
        match self.bits {
            false => Nsp::Inactive,
            true => Nsp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Nsp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Nsp::Active
    }
}
#[doc = "Field `nsp` writer - Indicates whether nSTATUS Pin has an active interrupt or not (after masking)."]
pub type NspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether CONF_DONE Pin has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cdp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Cdp> for bool {
    #[inline(always)]
    fn from(variant: Cdp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cdp` reader - Indicates whether CONF_DONE Pin has an active interrupt or not (after masking)."]
pub type CdpR = crate::BitReader<Cdp>;
impl CdpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cdp {
        match self.bits {
            false => Cdp::Inactive,
            true => Cdp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Cdp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Cdp::Active
    }
}
#[doc = "Field `cdp` writer - Indicates whether CONF_DONE Pin has an active interrupt or not (after masking)."]
pub type CdpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates whether FPGA_POWER_ON has an active interrupt or not (after masking).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpo {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Fpo> for bool {
    #[inline(always)]
    fn from(variant: Fpo) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpo` reader - Indicates whether FPGA_POWER_ON has an active interrupt or not (after masking)."]
pub type FpoR = crate::BitReader<Fpo>;
impl FpoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fpo {
        match self.bits {
            false => Fpo::Inactive,
            true => Fpo::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Fpo::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Fpo::Active
    }
}
#[doc = "Field `fpo` writer - Indicates whether FPGA_POWER_ON has an active interrupt or not (after masking)."]
pub type FpoW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Indicates whether nSTATUS has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn ns(&self) -> NsR {
        NsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Indicates whether CONF_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Indicates whether INIT_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Indicates whether CRC_ERROR has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn crc(&self) -> CrcR {
        CrcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Indicates whether CVP_CONF_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn ccd(&self) -> CcdR {
        CcdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Indicates whether PR_READY has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn prr(&self) -> PrrR {
        PrrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Indicates whether PR_ERROR has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn pre(&self) -> PreR {
        PreR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Indicates whether PR_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn prd(&self) -> PrdR {
        PrdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Indicates whether nCONFIG Pin has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn ncp(&self) -> NcpR {
        NcpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Indicates whether nSTATUS Pin has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn nsp(&self) -> NspR {
        NspR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Indicates whether CONF_DONE Pin has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn cdp(&self) -> CdpR {
        CdpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Indicates whether FPGA_POWER_ON has an active interrupt or not (after masking)."]
    #[inline(always)]
    pub fn fpo(&self) -> FpoR {
        FpoR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Indicates whether nSTATUS has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn ns(&mut self) -> NsW<MonGpioIntstatusSpec> {
        NsW::new(self, 0)
    }
    #[doc = "Bit 1 - Indicates whether CONF_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MonGpioIntstatusSpec> {
        CdW::new(self, 1)
    }
    #[doc = "Bit 2 - Indicates whether INIT_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MonGpioIntstatusSpec> {
        IdW::new(self, 2)
    }
    #[doc = "Bit 3 - Indicates whether CRC_ERROR has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn crc(&mut self) -> CrcW<MonGpioIntstatusSpec> {
        CrcW::new(self, 3)
    }
    #[doc = "Bit 4 - Indicates whether CVP_CONF_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn ccd(&mut self) -> CcdW<MonGpioIntstatusSpec> {
        CcdW::new(self, 4)
    }
    #[doc = "Bit 5 - Indicates whether PR_READY has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn prr(&mut self) -> PrrW<MonGpioIntstatusSpec> {
        PrrW::new(self, 5)
    }
    #[doc = "Bit 6 - Indicates whether PR_ERROR has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn pre(&mut self) -> PreW<MonGpioIntstatusSpec> {
        PreW::new(self, 6)
    }
    #[doc = "Bit 7 - Indicates whether PR_DONE has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn prd(&mut self) -> PrdW<MonGpioIntstatusSpec> {
        PrdW::new(self, 7)
    }
    #[doc = "Bit 8 - Indicates whether nCONFIG Pin has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn ncp(&mut self) -> NcpW<MonGpioIntstatusSpec> {
        NcpW::new(self, 8)
    }
    #[doc = "Bit 9 - Indicates whether nSTATUS Pin has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn nsp(&mut self) -> NspW<MonGpioIntstatusSpec> {
        NspW::new(self, 9)
    }
    #[doc = "Bit 10 - Indicates whether CONF_DONE Pin has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn cdp(&mut self) -> CdpW<MonGpioIntstatusSpec> {
        CdpW::new(self, 10)
    }
    #[doc = "Bit 11 - Indicates whether FPGA_POWER_ON has an active interrupt or not (after masking)."]
    #[inline(always)]
    #[must_use]
    pub fn fpo(&mut self) -> FpoW<MonGpioIntstatusSpec> {
        FpoW::new(self, 11)
    }
}
#[doc = "Reports on interrupt status for each GPIO input. The interrupt status includes the effects of masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_intstatus::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioIntstatusSpec;
impl crate::RegisterSpec for MonGpioIntstatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 2112u64;
}
#[doc = "`read()` method returns [`mon_gpio_intstatus::R`](R) reader structure"]
impl crate::Readable for MonGpioIntstatusSpec {}
#[doc = "`reset()` method sets mon_gpio_intstatus to value 0"]
impl crate::Resettable for MonGpioIntstatusSpec {
    const RESET_VALUE: u32 = 0;
}
