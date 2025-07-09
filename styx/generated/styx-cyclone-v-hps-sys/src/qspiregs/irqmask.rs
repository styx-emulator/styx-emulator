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
#[doc = "Register `irqmask` reader"]
pub type R = crate::R<IrqmaskSpec>;
#[doc = "Register `irqmask` writer"]
pub type W = crate::W<IrqmaskSpec>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Underflowdet {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Underflowdet> for bool {
    #[inline(always)]
    fn from(variant: Underflowdet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `underflowdet` reader - "]
pub type UnderflowdetR = crate::BitReader<Underflowdet>;
impl UnderflowdetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Underflowdet {
        match self.bits {
            false => Underflowdet::Disabled,
            true => Underflowdet::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Underflowdet::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Underflowdet::Enabled
    }
}
#[doc = "Field `underflowdet` writer - "]
pub type UnderflowdetW<'a, REG> = crate::BitWriter<'a, REG, Underflowdet>;
impl<'a, REG> UnderflowdetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Underflowdet::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Underflowdet::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indopdone {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Indopdone> for bool {
    #[inline(always)]
    fn from(variant: Indopdone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indopdone` reader - "]
pub type IndopdoneR = crate::BitReader<Indopdone>;
impl IndopdoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indopdone {
        match self.bits {
            false => Indopdone::Disabled,
            true => Indopdone::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Indopdone::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Indopdone::Enabled
    }
}
#[doc = "Field `indopdone` writer - "]
pub type IndopdoneW<'a, REG> = crate::BitWriter<'a, REG, Indopdone>;
impl<'a, REG> IndopdoneW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indopdone::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indopdone::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indrdreject {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Indrdreject> for bool {
    #[inline(always)]
    fn from(variant: Indrdreject) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indrdreject` reader - "]
pub type IndrdrejectR = crate::BitReader<Indrdreject>;
impl IndrdrejectR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indrdreject {
        match self.bits {
            false => Indrdreject::Disabled,
            true => Indrdreject::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Indrdreject::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Indrdreject::Enabled
    }
}
#[doc = "Field `indrdreject` writer - "]
pub type IndrdrejectW<'a, REG> = crate::BitWriter<'a, REG, Indrdreject>;
impl<'a, REG> IndrdrejectW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indrdreject::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indrdreject::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protwrattempt {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Protwrattempt> for bool {
    #[inline(always)]
    fn from(variant: Protwrattempt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `protwrattempt` reader - "]
pub type ProtwrattemptR = crate::BitReader<Protwrattempt>;
impl ProtwrattemptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Protwrattempt {
        match self.bits {
            false => Protwrattempt::Disabled,
            true => Protwrattempt::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Protwrattempt::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Protwrattempt::Enabled
    }
}
#[doc = "Field `protwrattempt` writer - "]
pub type ProtwrattemptW<'a, REG> = crate::BitWriter<'a, REG, Protwrattempt>;
impl<'a, REG> ProtwrattemptW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Protwrattempt::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Protwrattempt::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Illegalacc {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Illegalacc> for bool {
    #[inline(always)]
    fn from(variant: Illegalacc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `illegalacc` reader - "]
pub type IllegalaccR = crate::BitReader<Illegalacc>;
impl IllegalaccR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Illegalacc {
        match self.bits {
            false => Illegalacc::Disabled,
            true => Illegalacc::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Illegalacc::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Illegalacc::Enabled
    }
}
#[doc = "Field `illegalacc` writer - "]
pub type IllegalaccW<'a, REG> = crate::BitWriter<'a, REG, Illegalacc>;
impl<'a, REG> IllegalaccW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Illegalacc::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Illegalacc::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indxfrlvl {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Indxfrlvl> for bool {
    #[inline(always)]
    fn from(variant: Indxfrlvl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indxfrlvl` reader - "]
pub type IndxfrlvlR = crate::BitReader<Indxfrlvl>;
impl IndxfrlvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indxfrlvl {
        match self.bits {
            false => Indxfrlvl::Disabled,
            true => Indxfrlvl::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Indxfrlvl::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Indxfrlvl::Enabled
    }
}
#[doc = "Field `indxfrlvl` writer - "]
pub type IndxfrlvlW<'a, REG> = crate::BitWriter<'a, REG, Indxfrlvl>;
impl<'a, REG> IndxfrlvlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indxfrlvl::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indxfrlvl::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxover {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxover> for bool {
    #[inline(always)]
    fn from(variant: Rxover) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxover` reader - "]
pub type RxoverR = crate::BitReader<Rxover>;
impl RxoverR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxover {
        match self.bits {
            false => Rxover::Disabled,
            true => Rxover::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxover::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxover::Enabled
    }
}
#[doc = "Field `rxover` writer - "]
pub type RxoverW<'a, REG> = crate::BitWriter<'a, REG, Rxover>;
impl<'a, REG> RxoverW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxover::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxover::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txthreshcmp {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txthreshcmp> for bool {
    #[inline(always)]
    fn from(variant: Txthreshcmp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txthreshcmp` reader - "]
pub type TxthreshcmpR = crate::BitReader<Txthreshcmp>;
impl TxthreshcmpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txthreshcmp {
        match self.bits {
            false => Txthreshcmp::Disabled,
            true => Txthreshcmp::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txthreshcmp::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txthreshcmp::Enabled
    }
}
#[doc = "Field `txthreshcmp` writer - "]
pub type TxthreshcmpW<'a, REG> = crate::BitWriter<'a, REG, Txthreshcmp>;
impl<'a, REG> TxthreshcmpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txthreshcmp::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txthreshcmp::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfull {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txfull> for bool {
    #[inline(always)]
    fn from(variant: Txfull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfull` reader - "]
pub type TxfullR = crate::BitReader<Txfull>;
impl TxfullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfull {
        match self.bits {
            false => Txfull::Disabled,
            true => Txfull::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txfull::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txfull::Enabled
    }
}
#[doc = "Field `txfull` writer - "]
pub type TxfullW<'a, REG> = crate::BitWriter<'a, REG, Txfull>;
impl<'a, REG> TxfullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txfull::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txfull::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxthreshcmp {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxthreshcmp> for bool {
    #[inline(always)]
    fn from(variant: Rxthreshcmp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxthreshcmp` reader - "]
pub type RxthreshcmpR = crate::BitReader<Rxthreshcmp>;
impl RxthreshcmpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxthreshcmp {
        match self.bits {
            false => Rxthreshcmp::Disabled,
            true => Rxthreshcmp::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxthreshcmp::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxthreshcmp::Enabled
    }
}
#[doc = "Field `rxthreshcmp` writer - "]
pub type RxthreshcmpW<'a, REG> = crate::BitWriter<'a, REG, Rxthreshcmp>;
impl<'a, REG> RxthreshcmpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxthreshcmp::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxthreshcmp::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfull {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxfull> for bool {
    #[inline(always)]
    fn from(variant: Rxfull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfull` reader - "]
pub type RxfullR = crate::BitReader<Rxfull>;
impl RxfullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfull {
        match self.bits {
            false => Rxfull::Disabled,
            true => Rxfull::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxfull::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxfull::Enabled
    }
}
#[doc = "Field `rxfull` writer - "]
pub type RxfullW<'a, REG> = crate::BitWriter<'a, REG, Rxfull>;
impl<'a, REG> RxfullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfull::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfull::Enabled)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indsramfull {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Indsramfull> for bool {
    #[inline(always)]
    fn from(variant: Indsramfull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indsramfull` reader - "]
pub type IndsramfullR = crate::BitReader<Indsramfull>;
impl IndsramfullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indsramfull {
        match self.bits {
            false => Indsramfull::Disabled,
            true => Indsramfull::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Indsramfull::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Indsramfull::Enabled
    }
}
#[doc = "Field `indsramfull` writer - "]
pub type IndsramfullW<'a, REG> = crate::BitWriter<'a, REG, Indsramfull>;
impl<'a, REG> IndsramfullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indsramfull::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Indsramfull::Enabled)
    }
}
impl R {
    #[doc = "Bit 1"]
    #[inline(always)]
    pub fn underflowdet(&self) -> UnderflowdetR {
        UnderflowdetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    pub fn indopdone(&self) -> IndopdoneR {
        IndopdoneR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    pub fn indrdreject(&self) -> IndrdrejectR {
        IndrdrejectR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    pub fn protwrattempt(&self) -> ProtwrattemptR {
        ProtwrattemptR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    pub fn illegalacc(&self) -> IllegalaccR {
        IllegalaccR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    pub fn indxfrlvl(&self) -> IndxfrlvlR {
        IndxfrlvlR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7"]
    #[inline(always)]
    pub fn rxover(&self) -> RxoverR {
        RxoverR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    pub fn txthreshcmp(&self) -> TxthreshcmpR {
        TxthreshcmpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    pub fn txfull(&self) -> TxfullR {
        TxfullR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10"]
    #[inline(always)]
    pub fn rxthreshcmp(&self) -> RxthreshcmpR {
        RxthreshcmpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11"]
    #[inline(always)]
    pub fn rxfull(&self) -> RxfullR {
        RxfullR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    pub fn indsramfull(&self) -> IndsramfullR {
        IndsramfullR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn underflowdet(&mut self) -> UnderflowdetW<IrqmaskSpec> {
        UnderflowdetW::new(self, 1)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    #[must_use]
    pub fn indopdone(&mut self) -> IndopdoneW<IrqmaskSpec> {
        IndopdoneW::new(self, 2)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    #[must_use]
    pub fn indrdreject(&mut self) -> IndrdrejectW<IrqmaskSpec> {
        IndrdrejectW::new(self, 3)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    #[must_use]
    pub fn protwrattempt(&mut self) -> ProtwrattemptW<IrqmaskSpec> {
        ProtwrattemptW::new(self, 4)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    #[must_use]
    pub fn illegalacc(&mut self) -> IllegalaccW<IrqmaskSpec> {
        IllegalaccW::new(self, 5)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    #[must_use]
    pub fn indxfrlvl(&mut self) -> IndxfrlvlW<IrqmaskSpec> {
        IndxfrlvlW::new(self, 6)
    }
    #[doc = "Bit 7"]
    #[inline(always)]
    #[must_use]
    pub fn rxover(&mut self) -> RxoverW<IrqmaskSpec> {
        RxoverW::new(self, 7)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    #[must_use]
    pub fn txthreshcmp(&mut self) -> TxthreshcmpW<IrqmaskSpec> {
        TxthreshcmpW::new(self, 8)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    #[must_use]
    pub fn txfull(&mut self) -> TxfullW<IrqmaskSpec> {
        TxfullW::new(self, 9)
    }
    #[doc = "Bit 10"]
    #[inline(always)]
    #[must_use]
    pub fn rxthreshcmp(&mut self) -> RxthreshcmpW<IrqmaskSpec> {
        RxthreshcmpW::new(self, 10)
    }
    #[doc = "Bit 11"]
    #[inline(always)]
    #[must_use]
    pub fn rxfull(&mut self) -> RxfullW<IrqmaskSpec> {
        RxfullW::new(self, 11)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    #[must_use]
    pub fn indsramfull(&mut self) -> IndsramfullW<IrqmaskSpec> {
        IndsramfullW::new(self, 12)
    }
}
#[doc = "If disabled, the interrupt for the corresponding interrupt status register bit is disabled. If enabled, the interrupt for the corresponding interrupt status register bit is enabled.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`irqmask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`irqmask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IrqmaskSpec;
impl crate::RegisterSpec for IrqmaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`irqmask::R`](R) reader structure"]
impl crate::Readable for IrqmaskSpec {}
#[doc = "`write(|w| ..)` method takes [`irqmask::W`](W) writer structure"]
impl crate::Writable for IrqmaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets irqmask to value 0"]
impl crate::Resettable for IrqmaskSpec {
    const RESET_VALUE: u32 = 0;
}
