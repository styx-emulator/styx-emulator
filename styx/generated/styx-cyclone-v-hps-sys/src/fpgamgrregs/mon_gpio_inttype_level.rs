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
#[doc = "Register `mon_gpio_inttype_level` reader"]
pub type R = crate::R<MonGpioInttypeLevelSpec>;
#[doc = "Register `mon_gpio_inttype_level` writer"]
pub type W = crate::W<MonGpioInttypeLevelSpec>;
#[doc = "Controls whether the level of nSTATUS or an edge on nSTATUS generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ns {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Ns> for bool {
    #[inline(always)]
    fn from(variant: Ns) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ns` reader - Controls whether the level of nSTATUS or an edge on nSTATUS generates an interrupt."]
pub type NsR = crate::BitReader<Ns>;
impl NsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ns {
        match self.bits {
            false => Ns::Level,
            true => Ns::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Ns::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Ns::Edge
    }
}
#[doc = "Field `ns` writer - Controls whether the level of nSTATUS or an edge on nSTATUS generates an interrupt."]
pub type NsW<'a, REG> = crate::BitWriter<'a, REG, Ns>;
impl<'a, REG> NsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Edge)
    }
}
#[doc = "Controls whether the level of CONF_DONE or an edge on CONF_DONE generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Controls whether the level of CONF_DONE or an edge on CONF_DONE generates an interrupt."]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Level,
            true => Cd::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Cd::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Cd::Edge
    }
}
#[doc = "Field `cd` writer - Controls whether the level of CONF_DONE or an edge on CONF_DONE generates an interrupt."]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG, Cd>;
impl<'a, REG> CdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Edge)
    }
}
#[doc = "Controls whether the level of INIT_DONE or an edge on INIT_DONE generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Id> for bool {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `id` reader - Controls whether the level of INIT_DONE or an edge on INIT_DONE generates an interrupt."]
pub type IdR = crate::BitReader<Id>;
impl IdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Id {
        match self.bits {
            false => Id::Level,
            true => Id::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Id::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Id::Edge
    }
}
#[doc = "Field `id` writer - Controls whether the level of INIT_DONE or an edge on INIT_DONE generates an interrupt."]
pub type IdW<'a, REG> = crate::BitWriter<'a, REG, Id>;
impl<'a, REG> IdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Edge)
    }
}
#[doc = "Controls whether the level of CRC_ERROR or an edge on CRC_ERROR generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crc {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Crc> for bool {
    #[inline(always)]
    fn from(variant: Crc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `crc` reader - Controls whether the level of CRC_ERROR or an edge on CRC_ERROR generates an interrupt."]
pub type CrcR = crate::BitReader<Crc>;
impl CrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Crc {
        match self.bits {
            false => Crc::Level,
            true => Crc::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Crc::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Crc::Edge
    }
}
#[doc = "Field `crc` writer - Controls whether the level of CRC_ERROR or an edge on CRC_ERROR generates an interrupt."]
pub type CrcW<'a, REG> = crate::BitWriter<'a, REG, Crc>;
impl<'a, REG> CrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Edge)
    }
}
#[doc = "Controls whether the level of CVP_CONF_DONE or an edge on CVP_CONF_DONE generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ccd {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Ccd> for bool {
    #[inline(always)]
    fn from(variant: Ccd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ccd` reader - Controls whether the level of CVP_CONF_DONE or an edge on CVP_CONF_DONE generates an interrupt."]
pub type CcdR = crate::BitReader<Ccd>;
impl CcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ccd {
        match self.bits {
            false => Ccd::Level,
            true => Ccd::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Ccd::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Ccd::Edge
    }
}
#[doc = "Field `ccd` writer - Controls whether the level of CVP_CONF_DONE or an edge on CVP_CONF_DONE generates an interrupt."]
pub type CcdW<'a, REG> = crate::BitWriter<'a, REG, Ccd>;
impl<'a, REG> CcdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Edge)
    }
}
#[doc = "Controls whether the level of PR_READY or an edge on PR_READY generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prr {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Prr> for bool {
    #[inline(always)]
    fn from(variant: Prr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prr` reader - Controls whether the level of PR_READY or an edge on PR_READY generates an interrupt."]
pub type PrrR = crate::BitReader<Prr>;
impl PrrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prr {
        match self.bits {
            false => Prr::Level,
            true => Prr::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Prr::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Prr::Edge
    }
}
#[doc = "Field `prr` writer - Controls whether the level of PR_READY or an edge on PR_READY generates an interrupt."]
pub type PrrW<'a, REG> = crate::BitWriter<'a, REG, Prr>;
impl<'a, REG> PrrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Edge)
    }
}
#[doc = "Controls whether the level of PR_ERROR or an edge on PR_ERROR generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pre {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Pre> for bool {
    #[inline(always)]
    fn from(variant: Pre) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pre` reader - Controls whether the level of PR_ERROR or an edge on PR_ERROR generates an interrupt."]
pub type PreR = crate::BitReader<Pre>;
impl PreR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pre {
        match self.bits {
            false => Pre::Level,
            true => Pre::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Pre::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Pre::Edge
    }
}
#[doc = "Field `pre` writer - Controls whether the level of PR_ERROR or an edge on PR_ERROR generates an interrupt."]
pub type PreW<'a, REG> = crate::BitWriter<'a, REG, Pre>;
impl<'a, REG> PreW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Edge)
    }
}
#[doc = "Controls whether the level of PR_DONE or an edge on PR_DONE generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prd {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Prd> for bool {
    #[inline(always)]
    fn from(variant: Prd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prd` reader - Controls whether the level of PR_DONE or an edge on PR_DONE generates an interrupt."]
pub type PrdR = crate::BitReader<Prd>;
impl PrdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prd {
        match self.bits {
            false => Prd::Level,
            true => Prd::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Prd::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Prd::Edge
    }
}
#[doc = "Field `prd` writer - Controls whether the level of PR_DONE or an edge on PR_DONE generates an interrupt."]
pub type PrdW<'a, REG> = crate::BitWriter<'a, REG, Prd>;
impl<'a, REG> PrdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Edge)
    }
}
#[doc = "Controls whether the level of nCONFIG Pin or an edge on nCONFIG Pin generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ncp {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Ncp> for bool {
    #[inline(always)]
    fn from(variant: Ncp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ncp` reader - Controls whether the level of nCONFIG Pin or an edge on nCONFIG Pin generates an interrupt."]
pub type NcpR = crate::BitReader<Ncp>;
impl NcpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ncp {
        match self.bits {
            false => Ncp::Level,
            true => Ncp::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Ncp::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Ncp::Edge
    }
}
#[doc = "Field `ncp` writer - Controls whether the level of nCONFIG Pin or an edge on nCONFIG Pin generates an interrupt."]
pub type NcpW<'a, REG> = crate::BitWriter<'a, REG, Ncp>;
impl<'a, REG> NcpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Edge)
    }
}
#[doc = "Controls whether the level of nSTATUS Pin or an edge on nSTATUS Pin generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nsp {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Nsp> for bool {
    #[inline(always)]
    fn from(variant: Nsp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nsp` reader - Controls whether the level of nSTATUS Pin or an edge on nSTATUS Pin generates an interrupt."]
pub type NspR = crate::BitReader<Nsp>;
impl NspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nsp {
        match self.bits {
            false => Nsp::Level,
            true => Nsp::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Nsp::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Nsp::Edge
    }
}
#[doc = "Field `nsp` writer - Controls whether the level of nSTATUS Pin or an edge on nSTATUS Pin generates an interrupt."]
pub type NspW<'a, REG> = crate::BitWriter<'a, REG, Nsp>;
impl<'a, REG> NspW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Edge)
    }
}
#[doc = "Controls whether the level of CONF_DONE Pin or an edge on CONF_DONE Pin generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cdp {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Cdp> for bool {
    #[inline(always)]
    fn from(variant: Cdp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cdp` reader - Controls whether the level of CONF_DONE Pin or an edge on CONF_DONE Pin generates an interrupt."]
pub type CdpR = crate::BitReader<Cdp>;
impl CdpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cdp {
        match self.bits {
            false => Cdp::Level,
            true => Cdp::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Cdp::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Cdp::Edge
    }
}
#[doc = "Field `cdp` writer - Controls whether the level of CONF_DONE Pin or an edge on CONF_DONE Pin generates an interrupt."]
pub type CdpW<'a, REG> = crate::BitWriter<'a, REG, Cdp>;
impl<'a, REG> CdpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Edge)
    }
}
#[doc = "Controls whether the level of FPGA_POWER_ON or an edge on FPGA_POWER_ON generates an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpo {
    #[doc = "0: `0`"]
    Level = 0,
    #[doc = "1: `1`"]
    Edge = 1,
}
impl From<Fpo> for bool {
    #[inline(always)]
    fn from(variant: Fpo) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpo` reader - Controls whether the level of FPGA_POWER_ON or an edge on FPGA_POWER_ON generates an interrupt."]
pub type FpoR = crate::BitReader<Fpo>;
impl FpoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fpo {
        match self.bits {
            false => Fpo::Level,
            true => Fpo::Edge,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_level(&self) -> bool {
        *self == Fpo::Level
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_edge(&self) -> bool {
        *self == Fpo::Edge
    }
}
#[doc = "Field `fpo` writer - Controls whether the level of FPGA_POWER_ON or an edge on FPGA_POWER_ON generates an interrupt."]
pub type FpoW<'a, REG> = crate::BitWriter<'a, REG, Fpo>;
impl<'a, REG> FpoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn level(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Level)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn edge(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Edge)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether the level of nSTATUS or an edge on nSTATUS generates an interrupt."]
    #[inline(always)]
    pub fn ns(&self) -> NsR {
        NsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether the level of CONF_DONE or an edge on CONF_DONE generates an interrupt."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether the level of INIT_DONE or an edge on INIT_DONE generates an interrupt."]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether the level of CRC_ERROR or an edge on CRC_ERROR generates an interrupt."]
    #[inline(always)]
    pub fn crc(&self) -> CrcR {
        CrcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls whether the level of CVP_CONF_DONE or an edge on CVP_CONF_DONE generates an interrupt."]
    #[inline(always)]
    pub fn ccd(&self) -> CcdR {
        CcdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Controls whether the level of PR_READY or an edge on PR_READY generates an interrupt."]
    #[inline(always)]
    pub fn prr(&self) -> PrrR {
        PrrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Controls whether the level of PR_ERROR or an edge on PR_ERROR generates an interrupt."]
    #[inline(always)]
    pub fn pre(&self) -> PreR {
        PreR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Controls whether the level of PR_DONE or an edge on PR_DONE generates an interrupt."]
    #[inline(always)]
    pub fn prd(&self) -> PrdR {
        PrdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Controls whether the level of nCONFIG Pin or an edge on nCONFIG Pin generates an interrupt."]
    #[inline(always)]
    pub fn ncp(&self) -> NcpR {
        NcpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Controls whether the level of nSTATUS Pin or an edge on nSTATUS Pin generates an interrupt."]
    #[inline(always)]
    pub fn nsp(&self) -> NspR {
        NspR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Controls whether the level of CONF_DONE Pin or an edge on CONF_DONE Pin generates an interrupt."]
    #[inline(always)]
    pub fn cdp(&self) -> CdpR {
        CdpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Controls whether the level of FPGA_POWER_ON or an edge on FPGA_POWER_ON generates an interrupt."]
    #[inline(always)]
    pub fn fpo(&self) -> FpoR {
        FpoR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether the level of nSTATUS or an edge on nSTATUS generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ns(&mut self) -> NsW<MonGpioInttypeLevelSpec> {
        NsW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether the level of CONF_DONE or an edge on CONF_DONE generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MonGpioInttypeLevelSpec> {
        CdW::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether the level of INIT_DONE or an edge on INIT_DONE generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MonGpioInttypeLevelSpec> {
        IdW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls whether the level of CRC_ERROR or an edge on CRC_ERROR generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn crc(&mut self) -> CrcW<MonGpioInttypeLevelSpec> {
        CrcW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls whether the level of CVP_CONF_DONE or an edge on CVP_CONF_DONE generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ccd(&mut self) -> CcdW<MonGpioInttypeLevelSpec> {
        CcdW::new(self, 4)
    }
    #[doc = "Bit 5 - Controls whether the level of PR_READY or an edge on PR_READY generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn prr(&mut self) -> PrrW<MonGpioInttypeLevelSpec> {
        PrrW::new(self, 5)
    }
    #[doc = "Bit 6 - Controls whether the level of PR_ERROR or an edge on PR_ERROR generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn pre(&mut self) -> PreW<MonGpioInttypeLevelSpec> {
        PreW::new(self, 6)
    }
    #[doc = "Bit 7 - Controls whether the level of PR_DONE or an edge on PR_DONE generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn prd(&mut self) -> PrdW<MonGpioInttypeLevelSpec> {
        PrdW::new(self, 7)
    }
    #[doc = "Bit 8 - Controls whether the level of nCONFIG Pin or an edge on nCONFIG Pin generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ncp(&mut self) -> NcpW<MonGpioInttypeLevelSpec> {
        NcpW::new(self, 8)
    }
    #[doc = "Bit 9 - Controls whether the level of nSTATUS Pin or an edge on nSTATUS Pin generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn nsp(&mut self) -> NspW<MonGpioInttypeLevelSpec> {
        NspW::new(self, 9)
    }
    #[doc = "Bit 10 - Controls whether the level of CONF_DONE Pin or an edge on CONF_DONE Pin generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cdp(&mut self) -> CdpW<MonGpioInttypeLevelSpec> {
        CdpW::new(self, 10)
    }
    #[doc = "Bit 11 - Controls whether the level of FPGA_POWER_ON or an edge on FPGA_POWER_ON generates an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn fpo(&mut self) -> FpoW<MonGpioInttypeLevelSpec> {
        FpoW::new(self, 11)
    }
}
#[doc = "The interrupt level register defines the type of interrupt (edge or level) for each GPIO input.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_inttype_level::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_inttype_level::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioInttypeLevelSpec;
impl crate::RegisterSpec for MonGpioInttypeLevelSpec {
    type Ux = u32;
    const OFFSET: u64 = 2104u64;
}
#[doc = "`read()` method returns [`mon_gpio_inttype_level::R`](R) reader structure"]
impl crate::Readable for MonGpioInttypeLevelSpec {}
#[doc = "`write(|w| ..)` method takes [`mon_gpio_inttype_level::W`](W) writer structure"]
impl crate::Writable for MonGpioInttypeLevelSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mon_gpio_inttype_level to value 0"]
impl crate::Resettable for MonGpioInttypeLevelSpec {
    const RESET_VALUE: u32 = 0;
}
