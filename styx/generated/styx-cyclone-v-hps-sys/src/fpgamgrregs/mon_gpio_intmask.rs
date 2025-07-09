// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mon_gpio_intmask` reader"]
pub type R = crate::R<MonGpioIntmaskSpec>;
#[doc = "Register `mon_gpio_intmask` writer"]
pub type W = crate::W<MonGpioIntmaskSpec>;
#[doc = "Controls whether an interrupt for nSTATUS can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ns {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ns> for bool {
    #[inline(always)]
    fn from(variant: Ns) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ns` reader - Controls whether an interrupt for nSTATUS can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type NsR = crate::BitReader<Ns>;
impl NsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ns {
        match self.bits {
            false => Ns::Disable,
            true => Ns::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ns::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ns::Enable
    }
}
#[doc = "Field `ns` writer - Controls whether an interrupt for nSTATUS can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type NsW<'a, REG> = crate::BitWriter<'a, REG, Ns>;
impl<'a, REG> NsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ns::Enable)
    }
}
#[doc = "Controls whether an interrupt for CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Controls whether an interrupt for CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Disable,
            true => Cd::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Cd::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Cd::Enable
    }
}
#[doc = "Field `cd` writer - Controls whether an interrupt for CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG, Cd>;
impl<'a, REG> CdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Cd::Enable)
    }
}
#[doc = "Controls whether an interrupt for INIT_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Id> for bool {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `id` reader - Controls whether an interrupt for INIT_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type IdR = crate::BitReader<Id>;
impl IdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Id {
        match self.bits {
            false => Id::Disable,
            true => Id::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Id::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Id::Enable
    }
}
#[doc = "Field `id` writer - Controls whether an interrupt for INIT_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type IdW<'a, REG> = crate::BitWriter<'a, REG, Id>;
impl<'a, REG> IdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Id::Enable)
    }
}
#[doc = "Controls whether an interrupt for CRC_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crc {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Crc> for bool {
    #[inline(always)]
    fn from(variant: Crc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `crc` reader - Controls whether an interrupt for CRC_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CrcR = crate::BitReader<Crc>;
impl CrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Crc {
        match self.bits {
            false => Crc::Disable,
            true => Crc::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Crc::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Crc::Enable
    }
}
#[doc = "Field `crc` writer - Controls whether an interrupt for CRC_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CrcW<'a, REG> = crate::BitWriter<'a, REG, Crc>;
impl<'a, REG> CrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Crc::Enable)
    }
}
#[doc = "Controls whether an interrupt for CVP_CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ccd {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ccd> for bool {
    #[inline(always)]
    fn from(variant: Ccd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ccd` reader - Controls whether an interrupt for CVP_CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CcdR = crate::BitReader<Ccd>;
impl CcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ccd {
        match self.bits {
            false => Ccd::Disable,
            true => Ccd::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ccd::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ccd::Enable
    }
}
#[doc = "Field `ccd` writer - Controls whether an interrupt for CVP_CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CcdW<'a, REG> = crate::BitWriter<'a, REG, Ccd>;
impl<'a, REG> CcdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ccd::Enable)
    }
}
#[doc = "Controls whether an interrupt for PR_READY can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prr {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Prr> for bool {
    #[inline(always)]
    fn from(variant: Prr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prr` reader - Controls whether an interrupt for PR_READY can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type PrrR = crate::BitReader<Prr>;
impl PrrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prr {
        match self.bits {
            false => Prr::Disable,
            true => Prr::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Prr::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Prr::Enable
    }
}
#[doc = "Field `prr` writer - Controls whether an interrupt for PR_READY can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type PrrW<'a, REG> = crate::BitWriter<'a, REG, Prr>;
impl<'a, REG> PrrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Prr::Enable)
    }
}
#[doc = "Controls whether an interrupt for PR_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pre {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Pre> for bool {
    #[inline(always)]
    fn from(variant: Pre) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pre` reader - Controls whether an interrupt for PR_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type PreR = crate::BitReader<Pre>;
impl PreR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pre {
        match self.bits {
            false => Pre::Disable,
            true => Pre::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Pre::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Pre::Enable
    }
}
#[doc = "Field `pre` writer - Controls whether an interrupt for PR_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type PreW<'a, REG> = crate::BitWriter<'a, REG, Pre>;
impl<'a, REG> PreW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Pre::Enable)
    }
}
#[doc = "Controls whether an interrupt for PR_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prd {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Prd> for bool {
    #[inline(always)]
    fn from(variant: Prd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prd` reader - Controls whether an interrupt for PR_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type PrdR = crate::BitReader<Prd>;
impl PrdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prd {
        match self.bits {
            false => Prd::Disable,
            true => Prd::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Prd::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Prd::Enable
    }
}
#[doc = "Field `prd` writer - Controls whether an interrupt for PR_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type PrdW<'a, REG> = crate::BitWriter<'a, REG, Prd>;
impl<'a, REG> PrdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Prd::Enable)
    }
}
#[doc = "Controls whether an interrupt for nCONFIG Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ncp {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Ncp> for bool {
    #[inline(always)]
    fn from(variant: Ncp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ncp` reader - Controls whether an interrupt for nCONFIG Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type NcpR = crate::BitReader<Ncp>;
impl NcpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ncp {
        match self.bits {
            false => Ncp::Disable,
            true => Ncp::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Ncp::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Ncp::Enable
    }
}
#[doc = "Field `ncp` writer - Controls whether an interrupt for nCONFIG Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type NcpW<'a, REG> = crate::BitWriter<'a, REG, Ncp>;
impl<'a, REG> NcpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Ncp::Enable)
    }
}
#[doc = "Controls whether an interrupt for nSTATUS Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nsp {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Nsp> for bool {
    #[inline(always)]
    fn from(variant: Nsp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nsp` reader - Controls whether an interrupt for nSTATUS Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type NspR = crate::BitReader<Nsp>;
impl NspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nsp {
        match self.bits {
            false => Nsp::Disable,
            true => Nsp::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Nsp::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Nsp::Enable
    }
}
#[doc = "Field `nsp` writer - Controls whether an interrupt for nSTATUS Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type NspW<'a, REG> = crate::BitWriter<'a, REG, Nsp>;
impl<'a, REG> NspW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Nsp::Enable)
    }
}
#[doc = "Controls whether an interrupt for CONF_DONE Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cdp {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Cdp> for bool {
    #[inline(always)]
    fn from(variant: Cdp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cdp` reader - Controls whether an interrupt for CONF_DONE Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CdpR = crate::BitReader<Cdp>;
impl CdpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cdp {
        match self.bits {
            false => Cdp::Disable,
            true => Cdp::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Cdp::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Cdp::Enable
    }
}
#[doc = "Field `cdp` writer - Controls whether an interrupt for CONF_DONE Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type CdpW<'a, REG> = crate::BitWriter<'a, REG, Cdp>;
impl<'a, REG> CdpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Cdp::Enable)
    }
}
#[doc = "Controls whether an interrupt for FPGA_POWER_ON can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fpo {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Fpo> for bool {
    #[inline(always)]
    fn from(variant: Fpo) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fpo` reader - Controls whether an interrupt for FPGA_POWER_ON can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type FpoR = crate::BitReader<Fpo>;
impl FpoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fpo {
        match self.bits {
            false => Fpo::Disable,
            true => Fpo::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Fpo::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Fpo::Enable
    }
}
#[doc = "Field `fpo` writer - Controls whether an interrupt for FPGA_POWER_ON can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type FpoW<'a, REG> = crate::BitWriter<'a, REG, Fpo>;
impl<'a, REG> FpoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Fpo::Enable)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether an interrupt for nSTATUS can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn ns(&self) -> NsR {
        NsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether an interrupt for CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether an interrupt for INIT_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether an interrupt for CRC_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn crc(&self) -> CrcR {
        CrcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls whether an interrupt for CVP_CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn ccd(&self) -> CcdR {
        CcdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Controls whether an interrupt for PR_READY can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn prr(&self) -> PrrR {
        PrrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Controls whether an interrupt for PR_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn pre(&self) -> PreR {
        PreR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Controls whether an interrupt for PR_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn prd(&self) -> PrdR {
        PrdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Controls whether an interrupt for nCONFIG Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn ncp(&self) -> NcpR {
        NcpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Controls whether an interrupt for nSTATUS Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn nsp(&self) -> NspR {
        NspR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Controls whether an interrupt for CONF_DONE Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn cdp(&self) -> CdpR {
        CdpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Controls whether an interrupt for FPGA_POWER_ON can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn fpo(&self) -> FpoR {
        FpoR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether an interrupt for nSTATUS can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn ns(&mut self) -> NsW<MonGpioIntmaskSpec> {
        NsW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether an interrupt for CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MonGpioIntmaskSpec> {
        CdW::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether an interrupt for INIT_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MonGpioIntmaskSpec> {
        IdW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls whether an interrupt for CRC_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn crc(&mut self) -> CrcW<MonGpioIntmaskSpec> {
        CrcW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls whether an interrupt for CVP_CONF_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn ccd(&mut self) -> CcdW<MonGpioIntmaskSpec> {
        CcdW::new(self, 4)
    }
    #[doc = "Bit 5 - Controls whether an interrupt for PR_READY can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn prr(&mut self) -> PrrW<MonGpioIntmaskSpec> {
        PrrW::new(self, 5)
    }
    #[doc = "Bit 6 - Controls whether an interrupt for PR_ERROR can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn pre(&mut self) -> PreW<MonGpioIntmaskSpec> {
        PreW::new(self, 6)
    }
    #[doc = "Bit 7 - Controls whether an interrupt for PR_DONE can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn prd(&mut self) -> PrdW<MonGpioIntmaskSpec> {
        PrdW::new(self, 7)
    }
    #[doc = "Bit 8 - Controls whether an interrupt for nCONFIG Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn ncp(&mut self) -> NcpW<MonGpioIntmaskSpec> {
        NcpW::new(self, 8)
    }
    #[doc = "Bit 9 - Controls whether an interrupt for nSTATUS Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn nsp(&mut self) -> NspW<MonGpioIntmaskSpec> {
        NspW::new(self, 9)
    }
    #[doc = "Bit 10 - Controls whether an interrupt for CONF_DONE Pin can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn cdp(&mut self) -> CdpW<MonGpioIntmaskSpec> {
        CdpW::new(self, 10)
    }
    #[doc = "Bit 11 - Controls whether an interrupt for FPGA_POWER_ON can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn fpo(&mut self) -> FpoW<MonGpioIntmaskSpec> {
        FpoW::new(self, 11)
    }
}
#[doc = "This register has 12 individual interrupt masks for the MON. Controls whether an interrupt on Port A can create an interrupt for the interrupt controller by not masking it. By default, all interrupts bits are unmasked. Whenever a 1 is written to a bit in this register, it masks the interrupt generation capability for this signal; otherwise interrupts are allowed through. The unmasked status can be read as well as the resultant status after masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_intmask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_intmask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioIntmaskSpec;
impl crate::RegisterSpec for MonGpioIntmaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 2100u64;
}
#[doc = "`read()` method returns [`mon_gpio_intmask::R`](R) reader structure"]
impl crate::Readable for MonGpioIntmaskSpec {}
#[doc = "`write(|w| ..)` method takes [`mon_gpio_intmask::W`](W) writer structure"]
impl crate::Writable for MonGpioIntmaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mon_gpio_intmask to value 0"]
impl crate::Resettable for MonGpioIntmaskSpec {
    const RESET_VALUE: u32 = 0;
}
