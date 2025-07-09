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
#[doc = "Register `dmagrp_Interrupt_Enable` reader"]
pub type R = crate::R<DmagrpInterruptEnableSpec>;
#[doc = "Register `dmagrp_Interrupt_Enable` writer"]
pub type W = crate::W<DmagrpInterruptEnableSpec>;
#[doc = "When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Interrupt is enabled. When this bit is reset, the Transmit Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tie {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tie> for bool {
    #[inline(always)]
    fn from(variant: Tie) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tie` reader - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Interrupt is enabled. When this bit is reset, the Transmit Interrupt is disabled."]
pub type TieR = crate::BitReader<Tie>;
impl TieR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tie {
        match self.bits {
            false => Tie::Disabled,
            true => Tie::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tie::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tie::Enabled
    }
}
#[doc = "Field `tie` writer - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Interrupt is enabled. When this bit is reset, the Transmit Interrupt is disabled."]
pub type TieW<'a, REG> = crate::BitWriter<'a, REG, Tie>;
impl<'a, REG> TieW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tie::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tie::Enabled)
    }
}
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmission Stopped Interrupt is enabled. When this bit is reset, the Transmission Stopped Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tse {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tse> for bool {
    #[inline(always)]
    fn from(variant: Tse) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tse` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmission Stopped Interrupt is enabled. When this bit is reset, the Transmission Stopped Interrupt is disabled."]
pub type TseR = crate::BitReader<Tse>;
impl TseR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tse {
        match self.bits {
            false => Tse::Disabled,
            true => Tse::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tse::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tse::Enabled
    }
}
#[doc = "Field `tse` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmission Stopped Interrupt is enabled. When this bit is reset, the Transmission Stopped Interrupt is disabled."]
pub type TseW<'a, REG> = crate::BitWriter<'a, REG, Tse>;
impl<'a, REG> TseW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tse::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tse::Enabled)
    }
}
#[doc = "When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Buffer Unavailable Interrupt is enabled. When this bit is reset, the Transmit Buffer Unavailable Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tue {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tue> for bool {
    #[inline(always)]
    fn from(variant: Tue) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tue` reader - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Buffer Unavailable Interrupt is enabled. When this bit is reset, the Transmit Buffer Unavailable Interrupt is disabled."]
pub type TueR = crate::BitReader<Tue>;
impl TueR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tue {
        match self.bits {
            false => Tue::Disabled,
            true => Tue::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tue::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tue::Enabled
    }
}
#[doc = "Field `tue` writer - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Buffer Unavailable Interrupt is enabled. When this bit is reset, the Transmit Buffer Unavailable Interrupt is disabled."]
pub type TueW<'a, REG> = crate::BitWriter<'a, REG, Tue>;
impl<'a, REG> TueW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tue::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tue::Enabled)
    }
}
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Jabber Timeout Interrupt is enabled. When this bit is reset, the Transmit Jabber Timeout Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tje {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tje> for bool {
    #[inline(always)]
    fn from(variant: Tje) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tje` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Jabber Timeout Interrupt is enabled. When this bit is reset, the Transmit Jabber Timeout Interrupt is disabled."]
pub type TjeR = crate::BitReader<Tje>;
impl TjeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tje {
        match self.bits {
            false => Tje::Disabled,
            true => Tje::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tje::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tje::Enabled
    }
}
#[doc = "Field `tje` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Jabber Timeout Interrupt is enabled. When this bit is reset, the Transmit Jabber Timeout Interrupt is disabled."]
pub type TjeW<'a, REG> = crate::BitWriter<'a, REG, Tje>;
impl<'a, REG> TjeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tje::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tje::Enabled)
    }
}
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Overflow Interrupt is enabled. When this bit is reset, the Overflow Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ove {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ove> for bool {
    #[inline(always)]
    fn from(variant: Ove) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ove` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Overflow Interrupt is enabled. When this bit is reset, the Overflow Interrupt is disabled."]
pub type OveR = crate::BitReader<Ove>;
impl OveR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ove {
        match self.bits {
            false => Ove::Disabled,
            true => Ove::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ove::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ove::Enabled
    }
}
#[doc = "Field `ove` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Overflow Interrupt is enabled. When this bit is reset, the Overflow Interrupt is disabled."]
pub type OveW<'a, REG> = crate::BitWriter<'a, REG, Ove>;
impl<'a, REG> OveW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ove::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ove::Enabled)
    }
}
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Underflow Interrupt is enabled. When this bit is reset, the Underflow Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Une {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Une> for bool {
    #[inline(always)]
    fn from(variant: Une) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `une` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Underflow Interrupt is enabled. When this bit is reset, the Underflow Interrupt is disabled."]
pub type UneR = crate::BitReader<Une>;
impl UneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Une {
        match self.bits {
            false => Une::Disabled,
            true => Une::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Une::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Une::Enabled
    }
}
#[doc = "Field `une` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Underflow Interrupt is enabled. When this bit is reset, the Underflow Interrupt is disabled."]
pub type UneW<'a, REG> = crate::BitWriter<'a, REG, Une>;
impl<'a, REG> UneW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Une::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Une::Enabled)
    }
}
#[doc = "When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Receive Interrupt is enabled. When this bit is reset, the Receive Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rie {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rie> for bool {
    #[inline(always)]
    fn from(variant: Rie) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rie` reader - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Receive Interrupt is enabled. When this bit is reset, the Receive Interrupt is disabled."]
pub type RieR = crate::BitReader<Rie>;
impl RieR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rie {
        match self.bits {
            false => Rie::Disabled,
            true => Rie::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rie::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rie::Enabled
    }
}
#[doc = "Field `rie` writer - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Receive Interrupt is enabled. When this bit is reset, the Receive Interrupt is disabled."]
pub type RieW<'a, REG> = crate::BitWriter<'a, REG, Rie>;
impl<'a, REG> RieW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rie::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rie::Enabled)
    }
}
#[doc = "Field `rue` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Buffer Unavailable Interrupt is enabled. When this bit is reset, the Receive Buffer Unavailable Interrupt is disabled."]
pub type RueR = crate::BitReader;
#[doc = "Field `rue` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Buffer Unavailable Interrupt is enabled. When this bit is reset, the Receive Buffer Unavailable Interrupt is disabled."]
pub type RueW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Stopped Interrupt is enabled. When this bit is reset, the Receive Stopped Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rse {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rse> for bool {
    #[inline(always)]
    fn from(variant: Rse) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rse` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Stopped Interrupt is enabled. When this bit is reset, the Receive Stopped Interrupt is disabled."]
pub type RseR = crate::BitReader<Rse>;
impl RseR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rse {
        match self.bits {
            false => Rse::Disabled,
            true => Rse::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rse::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rse::Enabled
    }
}
#[doc = "Field `rse` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Stopped Interrupt is enabled. When this bit is reset, the Receive Stopped Interrupt is disabled."]
pub type RseW<'a, REG> = crate::BitWriter<'a, REG, Rse>;
impl<'a, REG> RseW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rse::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rse::Enabled)
    }
}
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Watchdog Timeout Interrupt is enabled. When this bit is reset, the Receive Watchdog Timeout Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rwe {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rwe> for bool {
    #[inline(always)]
    fn from(variant: Rwe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rwe` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Watchdog Timeout Interrupt is enabled. When this bit is reset, the Receive Watchdog Timeout Interrupt is disabled."]
pub type RweR = crate::BitReader<Rwe>;
impl RweR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rwe {
        match self.bits {
            false => Rwe::Disabled,
            true => Rwe::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rwe::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rwe::Enabled
    }
}
#[doc = "Field `rwe` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Watchdog Timeout Interrupt is enabled. When this bit is reset, the Receive Watchdog Timeout Interrupt is disabled."]
pub type RweW<'a, REG> = crate::BitWriter<'a, REG, Rwe>;
impl<'a, REG> RweW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rwe::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rwe::Enabled)
    }
}
#[doc = "When this bit is set with an Abnormal Interrupt Summary Enable (Bit 15), the Early Transmit Interrupt is enabled. When this bit is reset, the Early Transmit Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ete {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ete> for bool {
    #[inline(always)]
    fn from(variant: Ete) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ete` reader - When this bit is set with an Abnormal Interrupt Summary Enable (Bit 15), the Early Transmit Interrupt is enabled. When this bit is reset, the Early Transmit Interrupt is disabled."]
pub type EteR = crate::BitReader<Ete>;
impl EteR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ete {
        match self.bits {
            false => Ete::Disabled,
            true => Ete::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ete::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ete::Enabled
    }
}
#[doc = "Field `ete` writer - When this bit is set with an Abnormal Interrupt Summary Enable (Bit 15), the Early Transmit Interrupt is enabled. When this bit is reset, the Early Transmit Interrupt is disabled."]
pub type EteW<'a, REG> = crate::BitWriter<'a, REG, Ete>;
impl<'a, REG> EteW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ete::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ete::Enabled)
    }
}
#[doc = "When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Fatal Bus Error Interrupt is enabled. When this bit is reset, the Fatal Bus Error Enable Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fbe {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Fbe> for bool {
    #[inline(always)]
    fn from(variant: Fbe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fbe` reader - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Fatal Bus Error Interrupt is enabled. When this bit is reset, the Fatal Bus Error Enable Interrupt is disabled."]
pub type FbeR = crate::BitReader<Fbe>;
impl FbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fbe {
        match self.bits {
            false => Fbe::Disabled,
            true => Fbe::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Fbe::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Fbe::Enabled
    }
}
#[doc = "Field `fbe` writer - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Fatal Bus Error Interrupt is enabled. When this bit is reset, the Fatal Bus Error Enable Interrupt is disabled."]
pub type FbeW<'a, REG> = crate::BitWriter<'a, REG, Fbe>;
impl<'a, REG> FbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fbe::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fbe::Enabled)
    }
}
#[doc = "When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Early Receive Interrupt is enabled. When this bit is reset, the Early Receive Interrupt is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ere {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ere> for bool {
    #[inline(always)]
    fn from(variant: Ere) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ere` reader - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Early Receive Interrupt is enabled. When this bit is reset, the Early Receive Interrupt is disabled."]
pub type EreR = crate::BitReader<Ere>;
impl EreR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ere {
        match self.bits {
            false => Ere::Disabled,
            true => Ere::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ere::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ere::Enabled
    }
}
#[doc = "Field `ere` writer - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Early Receive Interrupt is enabled. When this bit is reset, the Early Receive Interrupt is disabled."]
pub type EreW<'a, REG> = crate::BitWriter<'a, REG, Ere>;
impl<'a, REG> EreW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ere::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ere::Enabled)
    }
}
#[doc = "When this bit is set, abnormal interrupt summary is enabled. When this bit is reset, the abnormal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aie {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Aie> for bool {
    #[inline(always)]
    fn from(variant: Aie) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `aie` reader - When this bit is set, abnormal interrupt summary is enabled. When this bit is reset, the abnormal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error"]
pub type AieR = crate::BitReader<Aie>;
impl AieR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Aie {
        match self.bits {
            false => Aie::Disabled,
            true => Aie::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Aie::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Aie::Enabled
    }
}
#[doc = "Field `aie` writer - When this bit is set, abnormal interrupt summary is enabled. When this bit is reset, the abnormal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error"]
pub type AieW<'a, REG> = crate::BitWriter<'a, REG, Aie>;
impl<'a, REG> AieW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Aie::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Aie::Enabled)
    }
}
#[doc = "When this bit is set, normal interrupt summary is enabled. When this bit is reset, normal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nie {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Nie> for bool {
    #[inline(always)]
    fn from(variant: Nie) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nie` reader - When this bit is set, normal interrupt summary is enabled. When this bit is reset, normal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt"]
pub type NieR = crate::BitReader<Nie>;
impl NieR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nie {
        match self.bits {
            false => Nie::Disabled,
            true => Nie::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Nie::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Nie::Enabled
    }
}
#[doc = "Field `nie` writer - When this bit is set, normal interrupt summary is enabled. When this bit is reset, normal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt"]
pub type NieW<'a, REG> = crate::BitWriter<'a, REG, Nie>;
impl<'a, REG> NieW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nie::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nie::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Interrupt is enabled. When this bit is reset, the Transmit Interrupt is disabled."]
    #[inline(always)]
    pub fn tie(&self) -> TieR {
        TieR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmission Stopped Interrupt is enabled. When this bit is reset, the Transmission Stopped Interrupt is disabled."]
    #[inline(always)]
    pub fn tse(&self) -> TseR {
        TseR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Buffer Unavailable Interrupt is enabled. When this bit is reset, the Transmit Buffer Unavailable Interrupt is disabled."]
    #[inline(always)]
    pub fn tue(&self) -> TueR {
        TueR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Jabber Timeout Interrupt is enabled. When this bit is reset, the Transmit Jabber Timeout Interrupt is disabled."]
    #[inline(always)]
    pub fn tje(&self) -> TjeR {
        TjeR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Overflow Interrupt is enabled. When this bit is reset, the Overflow Interrupt is disabled."]
    #[inline(always)]
    pub fn ove(&self) -> OveR {
        OveR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Underflow Interrupt is enabled. When this bit is reset, the Underflow Interrupt is disabled."]
    #[inline(always)]
    pub fn une(&self) -> UneR {
        UneR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Receive Interrupt is enabled. When this bit is reset, the Receive Interrupt is disabled."]
    #[inline(always)]
    pub fn rie(&self) -> RieR {
        RieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Buffer Unavailable Interrupt is enabled. When this bit is reset, the Receive Buffer Unavailable Interrupt is disabled."]
    #[inline(always)]
    pub fn rue(&self) -> RueR {
        RueR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Stopped Interrupt is enabled. When this bit is reset, the Receive Stopped Interrupt is disabled."]
    #[inline(always)]
    pub fn rse(&self) -> RseR {
        RseR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Watchdog Timeout Interrupt is enabled. When this bit is reset, the Receive Watchdog Timeout Interrupt is disabled."]
    #[inline(always)]
    pub fn rwe(&self) -> RweR {
        RweR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - When this bit is set with an Abnormal Interrupt Summary Enable (Bit 15), the Early Transmit Interrupt is enabled. When this bit is reset, the Early Transmit Interrupt is disabled."]
    #[inline(always)]
    pub fn ete(&self) -> EteR {
        EteR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 13 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Fatal Bus Error Interrupt is enabled. When this bit is reset, the Fatal Bus Error Enable Interrupt is disabled."]
    #[inline(always)]
    pub fn fbe(&self) -> FbeR {
        FbeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Early Receive Interrupt is enabled. When this bit is reset, the Early Receive Interrupt is disabled."]
    #[inline(always)]
    pub fn ere(&self) -> EreR {
        EreR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - When this bit is set, abnormal interrupt summary is enabled. When this bit is reset, the abnormal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error"]
    #[inline(always)]
    pub fn aie(&self) -> AieR {
        AieR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - When this bit is set, normal interrupt summary is enabled. When this bit is reset, normal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt"]
    #[inline(always)]
    pub fn nie(&self) -> NieR {
        NieR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Interrupt is enabled. When this bit is reset, the Transmit Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn tie(&mut self) -> TieW<DmagrpInterruptEnableSpec> {
        TieW::new(self, 0)
    }
    #[doc = "Bit 1 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmission Stopped Interrupt is enabled. When this bit is reset, the Transmission Stopped Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn tse(&mut self) -> TseW<DmagrpInterruptEnableSpec> {
        TseW::new(self, 1)
    }
    #[doc = "Bit 2 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Transmit Buffer Unavailable Interrupt is enabled. When this bit is reset, the Transmit Buffer Unavailable Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn tue(&mut self) -> TueW<DmagrpInterruptEnableSpec> {
        TueW::new(self, 2)
    }
    #[doc = "Bit 3 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Jabber Timeout Interrupt is enabled. When this bit is reset, the Transmit Jabber Timeout Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn tje(&mut self) -> TjeW<DmagrpInterruptEnableSpec> {
        TjeW::new(self, 3)
    }
    #[doc = "Bit 4 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Overflow Interrupt is enabled. When this bit is reset, the Overflow Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn ove(&mut self) -> OveW<DmagrpInterruptEnableSpec> {
        OveW::new(self, 4)
    }
    #[doc = "Bit 5 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Transmit Underflow Interrupt is enabled. When this bit is reset, the Underflow Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn une(&mut self) -> UneW<DmagrpInterruptEnableSpec> {
        UneW::new(self, 5)
    }
    #[doc = "Bit 6 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Receive Interrupt is enabled. When this bit is reset, the Receive Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn rie(&mut self) -> RieW<DmagrpInterruptEnableSpec> {
        RieW::new(self, 6)
    }
    #[doc = "Bit 7 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Buffer Unavailable Interrupt is enabled. When this bit is reset, the Receive Buffer Unavailable Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn rue(&mut self) -> RueW<DmagrpInterruptEnableSpec> {
        RueW::new(self, 7)
    }
    #[doc = "Bit 8 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Stopped Interrupt is enabled. When this bit is reset, the Receive Stopped Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn rse(&mut self) -> RseW<DmagrpInterruptEnableSpec> {
        RseW::new(self, 8)
    }
    #[doc = "Bit 9 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Receive Watchdog Timeout Interrupt is enabled. When this bit is reset, the Receive Watchdog Timeout Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn rwe(&mut self) -> RweW<DmagrpInterruptEnableSpec> {
        RweW::new(self, 9)
    }
    #[doc = "Bit 10 - When this bit is set with an Abnormal Interrupt Summary Enable (Bit 15), the Early Transmit Interrupt is enabled. When this bit is reset, the Early Transmit Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn ete(&mut self) -> EteW<DmagrpInterruptEnableSpec> {
        EteW::new(self, 10)
    }
    #[doc = "Bit 13 - When this bit is set with Abnormal Interrupt Summary Enable (Bit 15), the Fatal Bus Error Interrupt is enabled. When this bit is reset, the Fatal Bus Error Enable Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn fbe(&mut self) -> FbeW<DmagrpInterruptEnableSpec> {
        FbeW::new(self, 13)
    }
    #[doc = "Bit 14 - When this bit is set with Normal Interrupt Summary Enable (Bit 16), the Early Receive Interrupt is enabled. When this bit is reset, the Early Receive Interrupt is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn ere(&mut self) -> EreW<DmagrpInterruptEnableSpec> {
        EreW::new(self, 14)
    }
    #[doc = "Bit 15 - When this bit is set, abnormal interrupt summary is enabled. When this bit is reset, the abnormal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error"]
    #[inline(always)]
    #[must_use]
    pub fn aie(&mut self) -> AieW<DmagrpInterruptEnableSpec> {
        AieW::new(self, 15)
    }
    #[doc = "Bit 16 - When this bit is set, normal interrupt summary is enabled. When this bit is reset, normal interrupt summary is disabled. This bit enables the following interrupts in Register 5 (Status Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn nie(&mut self) -> NieW<DmagrpInterruptEnableSpec> {
        NieW::new(self, 16)
    }
}
#[doc = "The Interrupt Enable register enables the interrupts reported by Register 5 (Status Register). Setting a bit to 1'b1 enables a corresponding interrupt. After a hardware or software reset, all interrupts are disabled.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_interrupt_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_interrupt_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpInterruptEnableSpec;
impl crate::RegisterSpec for DmagrpInterruptEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 4124u64;
}
#[doc = "`read()` method returns [`dmagrp_interrupt_enable::R`](R) reader structure"]
impl crate::Readable for DmagrpInterruptEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_interrupt_enable::W`](W) writer structure"]
impl crate::Writable for DmagrpInterruptEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Interrupt_Enable to value 0"]
impl crate::Resettable for DmagrpInterruptEnableSpec {
    const RESET_VALUE: u32 = 0;
}
