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
#[doc = "Register `mintsts` reader"]
pub type R = crate::R<MintstsSpec>;
#[doc = "Register `mintsts` writer"]
pub type W = crate::W<MintstsSpec>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cd {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Cd> for bool {
    #[inline(always)]
    fn from(variant: Cd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cd` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type CdR = crate::BitReader<Cd>;
impl CdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cd {
        match self.bits {
            false => Cd::Mask,
            true => Cd::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Cd::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Cd::Nomask
    }
}
#[doc = "Field `cd` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type CdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resp {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Resp> for bool {
    #[inline(always)]
    fn from(variant: Resp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `resp` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type RespR = crate::BitReader<Resp>;
impl RespR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Resp {
        match self.bits {
            false => Resp::Mask,
            true => Resp::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Resp::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Resp::Nomask
    }
}
#[doc = "Field `resp` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type RespW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmdDone {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<CmdDone> for bool {
    #[inline(always)]
    fn from(variant: CmdDone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cmd_done` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type CmdDoneR = crate::BitReader<CmdDone>;
impl CmdDoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CmdDone {
        match self.bits {
            false => CmdDone::Mask,
            true => CmdDone::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == CmdDone::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == CmdDone::Nomask
    }
}
#[doc = "Field `cmd_done` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type CmdDoneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dt {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Dt> for bool {
    #[inline(always)]
    fn from(variant: Dt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dt` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DtR = crate::BitReader<Dt>;
impl DtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dt {
        match self.bits {
            false => Dt::Mask,
            true => Dt::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Dt::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Dt::Nomask
    }
}
#[doc = "Field `dt` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dttxfifodr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Dttxfifodr> for bool {
    #[inline(always)]
    fn from(variant: Dttxfifodr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dttxfifodr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DttxfifodrR = crate::BitReader<Dttxfifodr>;
impl DttxfifodrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dttxfifodr {
        match self.bits {
            false => Dttxfifodr::Mask,
            true => Dttxfifodr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Dttxfifodr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Dttxfifodr::Nomask
    }
}
#[doc = "Field `dttxfifodr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DttxfifodrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfifodr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Rxfifodr> for bool {
    #[inline(always)]
    fn from(variant: Rxfifodr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfifodr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type RxfifodrR = crate::BitReader<Rxfifodr>;
impl RxfifodrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfifodr {
        match self.bits {
            false => Rxfifodr::Mask,
            true => Rxfifodr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Rxfifodr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Rxfifodr::Nomask
    }
}
#[doc = "Field `rxfifodr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type RxfifodrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Respcrcerr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Respcrcerr> for bool {
    #[inline(always)]
    fn from(variant: Respcrcerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `respcrcerr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type RespcrcerrR = crate::BitReader<Respcrcerr>;
impl RespcrcerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Respcrcerr {
        match self.bits {
            false => Respcrcerr::Mask,
            true => Respcrcerr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Respcrcerr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Respcrcerr::Nomask
    }
}
#[doc = "Field `respcrcerr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type RespcrcerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Datacrcerr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Datacrcerr> for bool {
    #[inline(always)]
    fn from(variant: Datacrcerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `datacrcerr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DatacrcerrR = crate::BitReader<Datacrcerr>;
impl DatacrcerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Datacrcerr {
        match self.bits {
            false => Datacrcerr::Mask,
            true => Datacrcerr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Datacrcerr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Datacrcerr::Nomask
    }
}
#[doc = "Field `datacrcerr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DatacrcerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Respto {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Respto> for bool {
    #[inline(always)]
    fn from(variant: Respto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `respto` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type ResptoR = crate::BitReader<Respto>;
impl ResptoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Respto {
        match self.bits {
            false => Respto::Mask,
            true => Respto::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Respto::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Respto::Nomask
    }
}
#[doc = "Field `respto` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type ResptoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Datardto {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Datardto> for bool {
    #[inline(always)]
    fn from(variant: Datardto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `datardto` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DatardtoR = crate::BitReader<Datardto>;
impl DatardtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Datardto {
        match self.bits {
            false => Datardto::Mask,
            true => Datardto::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Datardto::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Datardto::Nomask
    }
}
#[doc = "Field `datardto` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DatardtoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dshto {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Dshto> for bool {
    #[inline(always)]
    fn from(variant: Dshto) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dshto` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DshtoR = crate::BitReader<Dshto>;
impl DshtoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dshto {
        match self.bits {
            false => Dshto::Mask,
            true => Dshto::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Dshto::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Dshto::Nomask
    }
}
#[doc = "Field `dshto` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type DshtoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fifoovunerr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Fifoovunerr> for bool {
    #[inline(always)]
    fn from(variant: Fifoovunerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifoovunerr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type FifoovunerrR = crate::BitReader<Fifoovunerr>;
impl FifoovunerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fifoovunerr {
        match self.bits {
            false => Fifoovunerr::Mask,
            true => Fifoovunerr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Fifoovunerr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Fifoovunerr::Nomask
    }
}
#[doc = "Field `fifoovunerr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type FifoovunerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hlwerr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Hlwerr> for bool {
    #[inline(always)]
    fn from(variant: Hlwerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hlwerr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type HlwerrR = crate::BitReader<Hlwerr>;
impl HlwerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hlwerr {
        match self.bits {
            false => Hlwerr::Mask,
            true => Hlwerr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Hlwerr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Hlwerr::Nomask
    }
}
#[doc = "Field `hlwerr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type HlwerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strerr {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Strerr> for bool {
    #[inline(always)]
    fn from(variant: Strerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `strerr` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type StrerrR = crate::BitReader<Strerr>;
impl StrerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Strerr {
        match self.bits {
            false => Strerr::Mask,
            true => Strerr::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Strerr::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Strerr::Nomask
    }
}
#[doc = "Field `strerr` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type StrerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acd {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Acd> for bool {
    #[inline(always)]
    fn from(variant: Acd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `acd` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type AcdR = crate::BitReader<Acd>;
impl AcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Acd {
        match self.bits {
            false => Acd::Mask,
            true => Acd::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Acd::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Acd::Nomask
    }
}
#[doc = "Field `acd` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type AcdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt enabled only if corresponding bit in interrupt mask register is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ebe {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Ebe> for bool {
    #[inline(always)]
    fn from(variant: Ebe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ebe` reader - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type EbeR = crate::BitReader<Ebe>;
impl EbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ebe {
        match self.bits {
            false => Ebe::Mask,
            true => Ebe::Nomask,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Ebe::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Ebe::Nomask
    }
}
#[doc = "Field `ebe` writer - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
pub type EbeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt from SDIO card: one bit for each card. Bit\\[16\\]
is for Card\\[0\\]. SDIO interrupt for card enabled only if corresponding sdio_int_mask bit is set in Interrupt mask register (mask bit 1 enables interrupt; 0 masks interrupt). In MMC-Ver3.3-only mode, bits always 0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdioInterrupt {
    #[doc = "1: `1`"]
    Active = 1,
    #[doc = "0: `0`"]
    Inactive = 0,
}
impl From<SdioInterrupt> for bool {
    #[inline(always)]
    fn from(variant: SdioInterrupt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sdio_interrupt` reader - Interrupt from SDIO card: one bit for each card. Bit\\[16\\]
is for Card\\[0\\]. SDIO interrupt for card enabled only if corresponding sdio_int_mask bit is set in Interrupt mask register (mask bit 1 enables interrupt; 0 masks interrupt). In MMC-Ver3.3-only mode, bits always 0."]
pub type SdioInterruptR = crate::BitReader<SdioInterrupt>;
impl SdioInterruptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SdioInterrupt {
        match self.bits {
            true => SdioInterrupt::Active,
            false => SdioInterrupt::Inactive,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == SdioInterrupt::Active
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == SdioInterrupt::Inactive
    }
}
#[doc = "Field `sdio_interrupt` writer - Interrupt from SDIO card: one bit for each card. Bit\\[16\\]
is for Card\\[0\\]. SDIO interrupt for card enabled only if corresponding sdio_int_mask bit is set in Interrupt mask register (mask bit 1 enables interrupt; 0 masks interrupt). In MMC-Ver3.3-only mode, bits always 0."]
pub type SdioInterruptW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn cd(&self) -> CdR {
        CdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn resp(&self) -> RespR {
        RespR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn cmd_done(&self) -> CmdDoneR {
        CmdDoneR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn dt(&self) -> DtR {
        DtR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn dttxfifodr(&self) -> DttxfifodrR {
        DttxfifodrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn rxfifodr(&self) -> RxfifodrR {
        RxfifodrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn respcrcerr(&self) -> RespcrcerrR {
        RespcrcerrR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn datacrcerr(&self) -> DatacrcerrR {
        DatacrcerrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn respto(&self) -> ResptoR {
        ResptoR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn datardto(&self) -> DatardtoR {
        DatardtoR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn dshto(&self) -> DshtoR {
        DshtoR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn fifoovunerr(&self) -> FifoovunerrR {
        FifoovunerrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn hlwerr(&self) -> HlwerrR {
        HlwerrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn strerr(&self) -> StrerrR {
        StrerrR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn acd(&self) -> AcdR {
        AcdR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    pub fn ebe(&self) -> EbeR {
        EbeR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Interrupt from SDIO card: one bit for each card. Bit\\[16\\]
is for Card\\[0\\]. SDIO interrupt for card enabled only if corresponding sdio_int_mask bit is set in Interrupt mask register (mask bit 1 enables interrupt; 0 masks interrupt). In MMC-Ver3.3-only mode, bits always 0."]
    #[inline(always)]
    pub fn sdio_interrupt(&self) -> SdioInterruptR {
        SdioInterruptR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn cd(&mut self) -> CdW<MintstsSpec> {
        CdW::new(self, 0)
    }
    #[doc = "Bit 1 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn resp(&mut self) -> RespW<MintstsSpec> {
        RespW::new(self, 1)
    }
    #[doc = "Bit 2 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn cmd_done(&mut self) -> CmdDoneW<MintstsSpec> {
        CmdDoneW::new(self, 2)
    }
    #[doc = "Bit 3 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn dt(&mut self) -> DtW<MintstsSpec> {
        DtW::new(self, 3)
    }
    #[doc = "Bit 4 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn dttxfifodr(&mut self) -> DttxfifodrW<MintstsSpec> {
        DttxfifodrW::new(self, 4)
    }
    #[doc = "Bit 5 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn rxfifodr(&mut self) -> RxfifodrW<MintstsSpec> {
        RxfifodrW::new(self, 5)
    }
    #[doc = "Bit 6 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn respcrcerr(&mut self) -> RespcrcerrW<MintstsSpec> {
        RespcrcerrW::new(self, 6)
    }
    #[doc = "Bit 7 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn datacrcerr(&mut self) -> DatacrcerrW<MintstsSpec> {
        DatacrcerrW::new(self, 7)
    }
    #[doc = "Bit 8 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn respto(&mut self) -> ResptoW<MintstsSpec> {
        ResptoW::new(self, 8)
    }
    #[doc = "Bit 9 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn datardto(&mut self) -> DatardtoW<MintstsSpec> {
        DatardtoW::new(self, 9)
    }
    #[doc = "Bit 10 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn dshto(&mut self) -> DshtoW<MintstsSpec> {
        DshtoW::new(self, 10)
    }
    #[doc = "Bit 11 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn fifoovunerr(&mut self) -> FifoovunerrW<MintstsSpec> {
        FifoovunerrW::new(self, 11)
    }
    #[doc = "Bit 12 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn hlwerr(&mut self) -> HlwerrW<MintstsSpec> {
        HlwerrW::new(self, 12)
    }
    #[doc = "Bit 13 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn strerr(&mut self) -> StrerrW<MintstsSpec> {
        StrerrW::new(self, 13)
    }
    #[doc = "Bit 14 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn acd(&mut self) -> AcdW<MintstsSpec> {
        AcdW::new(self, 14)
    }
    #[doc = "Bit 15 - Interrupt enabled only if corresponding bit in interrupt mask register is set."]
    #[inline(always)]
    #[must_use]
    pub fn ebe(&mut self) -> EbeW<MintstsSpec> {
        EbeW::new(self, 15)
    }
    #[doc = "Bit 16 - Interrupt from SDIO card: one bit for each card. Bit\\[16\\]
is for Card\\[0\\]. SDIO interrupt for card enabled only if corresponding sdio_int_mask bit is set in Interrupt mask register (mask bit 1 enables interrupt; 0 masks interrupt). In MMC-Ver3.3-only mode, bits always 0."]
    #[inline(always)]
    #[must_use]
    pub fn sdio_interrupt(&mut self) -> SdioInterruptW<MintstsSpec> {
        SdioInterruptW::new(self, 16)
    }
}
#[doc = "Describes state of Masked Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mintsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MintstsSpec;
impl crate::RegisterSpec for MintstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`mintsts::R`](R) reader structure"]
impl crate::Readable for MintstsSpec {}
#[doc = "`reset()` method sets mintsts to value 0"]
impl crate::Resettable for MintstsSpec {
    const RESET_VALUE: u32 = 0;
}
