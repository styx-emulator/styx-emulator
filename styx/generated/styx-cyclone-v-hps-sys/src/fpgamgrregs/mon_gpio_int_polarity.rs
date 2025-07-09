// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mon_gpio_int_polarity` reader"]
pub type R = crate::R<MonGpioIntPolaritySpec>;
#[doc = "Register `mon_gpio_int_polarity` writer"]
pub type W = crate::W<MonGpioIntPolaritySpec>;
#[doc = "Controls the polarity of edge or level sensitivity for nSTATUS\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ns {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Ns> for bool {
    #[inline(always)]
    fn from(variant: Ns) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ns` reader - Controls the polarity of edge or level sensitivity for nSTATUS"]
pub type NsR = crate::BitReader<Ns>;
impl NsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ns {
        match self.bits {
            false => Ns::Actlow,
            true => Ns::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Ns::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Ns::Acthigh
    }
}
#[doc = "Field `ns` writer - Controls the polarity of edge or level sensitivity for nSTATUS"]
pub type NsW<'a, REG> = crate::BitWriter<'a, REG, Ns>;
impl<'a, REG> NsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for CONF_DONE\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Controls the polarity of edge or level sensitivity for CONF_DONE"]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Actlow,
            true => Cd::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Cd::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Cd::Acthigh
    }
}
#[doc = "Field `cd` writer - Controls the polarity of edge or level sensitivity for CONF_DONE"]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG, Cd>;
impl<'a, REG> CdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for INIT_DONE\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Id> for bool {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `id` reader - Controls the polarity of edge or level sensitivity for INIT_DONE"]
pub type IdR = crate::BitReader<Id>;
impl IdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Id {
        match self.bits {
            false => Id::Actlow,
            true => Id::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Id::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Id::Acthigh
    }
}
#[doc = "Field `id` writer - Controls the polarity of edge or level sensitivity for INIT_DONE"]
pub type IdW<'a, REG> = crate::BitWriter<'a, REG, Id>;
impl<'a, REG> IdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for CRC_ERROR\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crc {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Crc> for bool {
    #[inline(always)]
    fn from(variant: Crc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `crc` reader - Controls the polarity of edge or level sensitivity for CRC_ERROR"]
pub type CrcR = crate::BitReader<Crc>;
impl CrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Crc {
        match self.bits {
            false => Crc::Actlow,
            true => Crc::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Crc::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Crc::Acthigh
    }
}
#[doc = "Field `crc` writer - Controls the polarity of edge or level sensitivity for CRC_ERROR"]
pub type CrcW<'a, REG> = crate::BitWriter<'a, REG, Crc>;
impl<'a, REG> CrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for CVP_CONF_DONE\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ccd {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Ccd> for bool {
    #[inline(always)]
    fn from(variant: Ccd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ccd` reader - Controls the polarity of edge or level sensitivity for CVP_CONF_DONE"]
pub type CcdR = crate::BitReader<Ccd>;
impl CcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ccd {
        match self.bits {
            false => Ccd::Actlow,
            true => Ccd::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Ccd::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Ccd::Acthigh
    }
}
#[doc = "Field `ccd` writer - Controls the polarity of edge or level sensitivity for CVP_CONF_DONE"]
pub type CcdW<'a, REG> = crate::BitWriter<'a, REG, Ccd>;
impl<'a, REG> CcdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for PR_READY\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prr {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Prr> for bool {
    #[inline(always)]
    fn from(variant: Prr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prr` reader - Controls the polarity of edge or level sensitivity for PR_READY"]
pub type PrrR = crate::BitReader<Prr>;
impl PrrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prr {
        match self.bits {
            false => Prr::Actlow,
            true => Prr::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Prr::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Prr::Acthigh
    }
}
#[doc = "Field `prr` writer - Controls the polarity of edge or level sensitivity for PR_READY"]
pub type PrrW<'a, REG> = crate::BitWriter<'a, REG, Prr>;
impl<'a, REG> PrrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for PR_ERROR\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pre {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Pre> for bool {
    #[inline(always)]
    fn from(variant: Pre) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pre` reader - Controls the polarity of edge or level sensitivity for PR_ERROR"]
pub type PreR = crate::BitReader<Pre>;
impl PreR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pre {
        match self.bits {
            false => Pre::Actlow,
            true => Pre::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Pre::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Pre::Acthigh
    }
}
#[doc = "Field `pre` writer - Controls the polarity of edge or level sensitivity for PR_ERROR"]
pub type PreW<'a, REG> = crate::BitWriter<'a, REG, Pre>;
impl<'a, REG> PreW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for PR_DONE\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prd {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Prd> for bool {
    #[inline(always)]
    fn from(variant: Prd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prd` reader - Controls the polarity of edge or level sensitivity for PR_DONE"]
pub type PrdR = crate::BitReader<Prd>;
impl PrdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prd {
        match self.bits {
            false => Prd::Actlow,
            true => Prd::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Prd::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Prd::Acthigh
    }
}
#[doc = "Field `prd` writer - Controls the polarity of edge or level sensitivity for PR_DONE"]
pub type PrdW<'a, REG> = crate::BitWriter<'a, REG, Prd>;
impl<'a, REG> PrdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for nCONFIG Pin\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ncp {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Ncp> for bool {
    #[inline(always)]
    fn from(variant: Ncp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ncp` reader - Controls the polarity of edge or level sensitivity for nCONFIG Pin"]
pub type NcpR = crate::BitReader<Ncp>;
impl NcpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ncp {
        match self.bits {
            false => Ncp::Actlow,
            true => Ncp::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Ncp::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Ncp::Acthigh
    }
}
#[doc = "Field `ncp` writer - Controls the polarity of edge or level sensitivity for nCONFIG Pin"]
pub type NcpW<'a, REG> = crate::BitWriter<'a, REG, Ncp>;
impl<'a, REG> NcpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for nSTATUS Pin\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nsp {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Nsp> for bool {
    #[inline(always)]
    fn from(variant: Nsp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nsp` reader - Controls the polarity of edge or level sensitivity for nSTATUS Pin"]
pub type NspR = crate::BitReader<Nsp>;
impl NspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nsp {
        match self.bits {
            false => Nsp::Actlow,
            true => Nsp::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Nsp::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Nsp::Acthigh
    }
}
#[doc = "Field `nsp` writer - Controls the polarity of edge or level sensitivity for nSTATUS Pin"]
pub type NspW<'a, REG> = crate::BitWriter<'a, REG, Nsp>;
impl<'a, REG> NspW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for CONF_DONE Pin\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cdp {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Cdp> for bool {
    #[inline(always)]
    fn from(variant: Cdp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cdp` reader - Controls the polarity of edge or level sensitivity for CONF_DONE Pin"]
pub type CdpR = crate::BitReader<Cdp>;
impl CdpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cdp {
        match self.bits {
            false => Cdp::Actlow,
            true => Cdp::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Cdp::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Cdp::Acthigh
    }
}
#[doc = "Field `cdp` writer - Controls the polarity of edge or level sensitivity for CONF_DONE Pin"]
pub type CdpW<'a, REG> = crate::BitWriter<'a, REG, Cdp>;
impl<'a, REG> CdpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Acthigh)
    }
}
#[doc = "Controls the polarity of edge or level sensitivity for FPGA_POWER_ON\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpo {
    #[doc = "0: `0`"]
    Actlow = 0,
    #[doc = "1: `1`"]
    Acthigh = 1,
}
impl From<Fpo> for bool {
    #[inline(always)]
    fn from(variant: Fpo) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpo` reader - Controls the polarity of edge or level sensitivity for FPGA_POWER_ON"]
pub type FpoR = crate::BitReader<Fpo>;
impl FpoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fpo {
        match self.bits {
            false => Fpo::Actlow,
            true => Fpo::Acthigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_actlow(&self) -> bool {
        *self == Fpo::Actlow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acthigh(&self) -> bool {
        *self == Fpo::Acthigh
    }
}
#[doc = "Field `fpo` writer - Controls the polarity of edge or level sensitivity for FPGA_POWER_ON"]
pub type FpoW<'a, REG> = crate::BitWriter<'a, REG, Fpo>;
impl<'a, REG> FpoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn actlow(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Actlow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn acthigh(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Acthigh)
    }
}
impl R {
    #[doc = "Bit 0 - Controls the polarity of edge or level sensitivity for nSTATUS"]
    #[inline(always)]
    pub fn ns(&self) -> NsR {
        NsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls the polarity of edge or level sensitivity for CONF_DONE"]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls the polarity of edge or level sensitivity for INIT_DONE"]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls the polarity of edge or level sensitivity for CRC_ERROR"]
    #[inline(always)]
    pub fn crc(&self) -> CrcR {
        CrcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls the polarity of edge or level sensitivity for CVP_CONF_DONE"]
    #[inline(always)]
    pub fn ccd(&self) -> CcdR {
        CcdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Controls the polarity of edge or level sensitivity for PR_READY"]
    #[inline(always)]
    pub fn prr(&self) -> PrrR {
        PrrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Controls the polarity of edge or level sensitivity for PR_ERROR"]
    #[inline(always)]
    pub fn pre(&self) -> PreR {
        PreR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Controls the polarity of edge or level sensitivity for PR_DONE"]
    #[inline(always)]
    pub fn prd(&self) -> PrdR {
        PrdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Controls the polarity of edge or level sensitivity for nCONFIG Pin"]
    #[inline(always)]
    pub fn ncp(&self) -> NcpR {
        NcpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Controls the polarity of edge or level sensitivity for nSTATUS Pin"]
    #[inline(always)]
    pub fn nsp(&self) -> NspR {
        NspR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Controls the polarity of edge or level sensitivity for CONF_DONE Pin"]
    #[inline(always)]
    pub fn cdp(&self) -> CdpR {
        CdpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Controls the polarity of edge or level sensitivity for FPGA_POWER_ON"]
    #[inline(always)]
    pub fn fpo(&self) -> FpoR {
        FpoR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls the polarity of edge or level sensitivity for nSTATUS"]
    #[inline(always)]
    #[must_use]
    pub fn ns(&mut self) -> NsW<MonGpioIntPolaritySpec> {
        NsW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls the polarity of edge or level sensitivity for CONF_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MonGpioIntPolaritySpec> {
        CdW::new(self, 1)
    }
    #[doc = "Bit 2 - Controls the polarity of edge or level sensitivity for INIT_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MonGpioIntPolaritySpec> {
        IdW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls the polarity of edge or level sensitivity for CRC_ERROR"]
    #[inline(always)]
    #[must_use]
    pub fn crc(&mut self) -> CrcW<MonGpioIntPolaritySpec> {
        CrcW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls the polarity of edge or level sensitivity for CVP_CONF_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn ccd(&mut self) -> CcdW<MonGpioIntPolaritySpec> {
        CcdW::new(self, 4)
    }
    #[doc = "Bit 5 - Controls the polarity of edge or level sensitivity for PR_READY"]
    #[inline(always)]
    #[must_use]
    pub fn prr(&mut self) -> PrrW<MonGpioIntPolaritySpec> {
        PrrW::new(self, 5)
    }
    #[doc = "Bit 6 - Controls the polarity of edge or level sensitivity for PR_ERROR"]
    #[inline(always)]
    #[must_use]
    pub fn pre(&mut self) -> PreW<MonGpioIntPolaritySpec> {
        PreW::new(self, 6)
    }
    #[doc = "Bit 7 - Controls the polarity of edge or level sensitivity for PR_DONE"]
    #[inline(always)]
    #[must_use]
    pub fn prd(&mut self) -> PrdW<MonGpioIntPolaritySpec> {
        PrdW::new(self, 7)
    }
    #[doc = "Bit 8 - Controls the polarity of edge or level sensitivity for nCONFIG Pin"]
    #[inline(always)]
    #[must_use]
    pub fn ncp(&mut self) -> NcpW<MonGpioIntPolaritySpec> {
        NcpW::new(self, 8)
    }
    #[doc = "Bit 9 - Controls the polarity of edge or level sensitivity for nSTATUS Pin"]
    #[inline(always)]
    #[must_use]
    pub fn nsp(&mut self) -> NspW<MonGpioIntPolaritySpec> {
        NspW::new(self, 9)
    }
    #[doc = "Bit 10 - Controls the polarity of edge or level sensitivity for CONF_DONE Pin"]
    #[inline(always)]
    #[must_use]
    pub fn cdp(&mut self) -> CdpW<MonGpioIntPolaritySpec> {
        CdpW::new(self, 10)
    }
    #[doc = "Bit 11 - Controls the polarity of edge or level sensitivity for FPGA_POWER_ON"]
    #[inline(always)]
    #[must_use]
    pub fn fpo(&mut self) -> FpoW<MonGpioIntPolaritySpec> {
        FpoW::new(self, 11)
    }
}
#[doc = "Controls the polarity of interrupts that can occur on each GPIO input.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_int_polarity::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_int_polarity::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioIntPolaritySpec;
impl crate::RegisterSpec for MonGpioIntPolaritySpec {
    type Ux = u32;
    const OFFSET: u64 = 2108u64;
}
#[doc = "`read()` method returns [`mon_gpio_int_polarity::R`](R) reader structure"]
impl crate::Readable for MonGpioIntPolaritySpec {}
#[doc = "`write(|w| ..)` method takes [`mon_gpio_int_polarity::W`](W) writer structure"]
impl crate::Writable for MonGpioIntPolaritySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mon_gpio_int_polarity to value 0"]
impl crate::Resettable for MonGpioIntPolaritySpec {
    const RESET_VALUE: u32 = 0;
}
