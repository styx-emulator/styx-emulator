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
#[doc = "Register `gmacgrp_MMC_Receive_Interrupt` reader"]
pub type R = crate::R<GmacgrpMmcReceiveInterruptSpec>;
#[doc = "Register `gmacgrp_MMC_Receive_Interrupt` writer"]
pub type W = crate::W<GmacgrpMmcReceiveInterruptSpec>;
#[doc = "This bit is set when the rxframecount_bg counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxgbfrmis {
    #[doc = "0: `0`"]
    Almosthalf = 0,
    #[doc = "1: `1`"]
    Almostfull = 1,
}
impl From<Rxgbfrmis> for bool {
    #[inline(always)]
    fn from(variant: Rxgbfrmis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxgbfrmis` reader - This bit is set when the rxframecount_bg counter reaches half of the maximum value or the maximum value."]
pub type RxgbfrmisR = crate::BitReader<Rxgbfrmis>;
impl RxgbfrmisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxgbfrmis {
        match self.bits {
            false => Rxgbfrmis::Almosthalf,
            true => Rxgbfrmis::Almostfull,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_almosthalf(&self) -> bool {
        *self == Rxgbfrmis::Almosthalf
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_almostfull(&self) -> bool {
        *self == Rxgbfrmis::Almostfull
    }
}
#[doc = "Field `rxgbfrmis` writer - This bit is set when the rxframecount_bg counter reaches half of the maximum value or the maximum value."]
pub type RxgbfrmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxoctetcount_bg counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxgboctis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxgboctis> for bool {
    #[inline(always)]
    fn from(variant: Rxgboctis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxgboctis` reader - This bit is set when the rxoctetcount_bg counter reaches half of the maximum value or the maximum value."]
pub type RxgboctisR = crate::BitReader<Rxgboctis>;
impl RxgboctisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxgboctis {
        match self.bits {
            false => Rxgboctis::Inactive,
            true => Rxgboctis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxgboctis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxgboctis::Active
    }
}
#[doc = "Field `rxgboctis` writer - This bit is set when the rxoctetcount_bg counter reaches half of the maximum value or the maximum value."]
pub type RxgboctisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxoctetcount_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxgoctis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxgoctis> for bool {
    #[inline(always)]
    fn from(variant: Rxgoctis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxgoctis` reader - This bit is set when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type RxgoctisR = crate::BitReader<Rxgoctis>;
impl RxgoctisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxgoctis {
        match self.bits {
            false => Rxgoctis::Inactive,
            true => Rxgoctis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxgoctis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxgoctis::Active
    }
}
#[doc = "Field `rxgoctis` writer - This bit is set when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type RxgoctisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rxbcgfis` reader - This bit is set when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxbcgfisR = crate::BitReader;
#[doc = "Field `rxbcgfis` writer - This bit is set when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxbcgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxmcgfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxmcgfis> for bool {
    #[inline(always)]
    fn from(variant: Rxmcgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxmcgfis` reader - This bit is set when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxmcgfisR = crate::BitReader<Rxmcgfis>;
impl RxmcgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxmcgfis {
        match self.bits {
            false => Rxmcgfis::Inactive,
            true => Rxmcgfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxmcgfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxmcgfis::Active
    }
}
#[doc = "Field `rxmcgfis` writer - This bit is set when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxmcgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxcrcerror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxcrcerfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxcrcerfis> for bool {
    #[inline(always)]
    fn from(variant: Rxcrcerfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxcrcerfis` reader - This bit is set when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
pub type RxcrcerfisR = crate::BitReader<Rxcrcerfis>;
impl RxcrcerfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxcrcerfis {
        match self.bits {
            false => Rxcrcerfis::Inactive,
            true => Rxcrcerfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxcrcerfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxcrcerfis::Active
    }
}
#[doc = "Field `rxcrcerfis` writer - This bit is set when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
pub type RxcrcerfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxalignmenterror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxalgnerfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxalgnerfis> for bool {
    #[inline(always)]
    fn from(variant: Rxalgnerfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxalgnerfis` reader - This bit is set when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
pub type RxalgnerfisR = crate::BitReader<Rxalgnerfis>;
impl RxalgnerfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxalgnerfis {
        match self.bits {
            false => Rxalgnerfis::Inactive,
            true => Rxalgnerfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxalgnerfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxalgnerfis::Active
    }
}
#[doc = "Field `rxalgnerfis` writer - This bit is set when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
pub type RxalgnerfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxrunterror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxruntfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxruntfis> for bool {
    #[inline(always)]
    fn from(variant: Rxruntfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxruntfis` reader - This bit is set when the rxrunterror counter reaches half of the maximum value or the maximum value."]
pub type RxruntfisR = crate::BitReader<Rxruntfis>;
impl RxruntfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxruntfis {
        match self.bits {
            false => Rxruntfis::Inactive,
            true => Rxruntfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxruntfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxruntfis::Active
    }
}
#[doc = "Field `rxruntfis` writer - This bit is set when the rxrunterror counter reaches half of the maximum value or the maximum value."]
pub type RxruntfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxjabbererror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxjaberfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxjaberfis> for bool {
    #[inline(always)]
    fn from(variant: Rxjaberfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxjaberfis` reader - This bit is set when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
pub type RxjaberfisR = crate::BitReader<Rxjaberfis>;
impl RxjaberfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxjaberfis {
        match self.bits {
            false => Rxjaberfis::Inactive,
            true => Rxjaberfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxjaberfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxjaberfis::Active
    }
}
#[doc = "Field `rxjaberfis` writer - This bit is set when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
pub type RxjaberfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxundersize_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxusizegfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxusizegfis> for bool {
    #[inline(always)]
    fn from(variant: Rxusizegfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxusizegfis` reader - This bit is set when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
pub type RxusizegfisR = crate::BitReader<Rxusizegfis>;
impl RxusizegfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxusizegfis {
        match self.bits {
            false => Rxusizegfis::Inactive,
            true => Rxusizegfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxusizegfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxusizegfis::Active
    }
}
#[doc = "Field `rxusizegfis` writer - This bit is set when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
pub type RxusizegfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxoversize_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxosizegfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxosizegfis> for bool {
    #[inline(always)]
    fn from(variant: Rxosizegfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxosizegfis` reader - This bit is set when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
pub type RxosizegfisR = crate::BitReader<Rxosizegfis>;
impl RxosizegfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxosizegfis {
        match self.bits {
            false => Rxosizegfis::Inactive,
            true => Rxosizegfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxosizegfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxosizegfis::Active
    }
}
#[doc = "Field `rxosizegfis` writer - This bit is set when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
pub type RxosizegfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rx64octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx64octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rx64octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Rx64octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx64octgbfis` reader - This bit is set when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx64octgbfisR = crate::BitReader<Rx64octgbfis>;
impl Rx64octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx64octgbfis {
        match self.bits {
            false => Rx64octgbfis::Inactive,
            true => Rx64octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rx64octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rx64octgbfis::Active
    }
}
#[doc = "Field `rx64octgbfis` writer - This bit is set when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx64octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is set when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx65t127octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rx65t127octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Rx65t127octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx65t127octgbfis` reader - This is set when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx65t127octgbfisR = crate::BitReader<Rx65t127octgbfis>;
impl Rx65t127octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx65t127octgbfis {
        match self.bits {
            false => Rx65t127octgbfis::Inactive,
            true => Rx65t127octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rx65t127octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rx65t127octgbfis::Active
    }
}
#[doc = "Field `rx65t127octgbfis` writer - This is set when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx65t127octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx128t255octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rx128t255octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Rx128t255octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx128t255octgbfis` reader - This bit is set when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx128t255octgbfisR = crate::BitReader<Rx128t255octgbfis>;
impl Rx128t255octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx128t255octgbfis {
        match self.bits {
            false => Rx128t255octgbfis::Inactive,
            true => Rx128t255octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rx128t255octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rx128t255octgbfis::Active
    }
}
#[doc = "Field `rx128t255octgbfis` writer - This bit is set when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx128t255octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx256t511octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rx256t511octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Rx256t511octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx256t511octgbfis` reader - This bit is set when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx256t511octgbfisR = crate::BitReader<Rx256t511octgbfis>;
impl Rx256t511octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx256t511octgbfis {
        match self.bits {
            false => Rx256t511octgbfis::Inactive,
            true => Rx256t511octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rx256t511octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rx256t511octgbfis::Active
    }
}
#[doc = "Field `rx256t511octgbfis` writer - This bit is set when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx256t511octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx512t1023octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rx512t1023octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Rx512t1023octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx512t1023octgbfis` reader - This bit is set when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx512t1023octgbfisR = crate::BitReader<Rx512t1023octgbfis>;
impl Rx512t1023octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx512t1023octgbfis {
        match self.bits {
            false => Rx512t1023octgbfis::Inactive,
            true => Rx512t1023octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rx512t1023octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rx512t1023octgbfis::Active
    }
}
#[doc = "Field `rx512t1023octgbfis` writer - This bit is set when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx512t1023octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx1024tmaxoctgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rx1024tmaxoctgbfis> for bool {
    #[inline(always)]
    fn from(variant: Rx1024tmaxoctgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rx1024tmaxoctgbfis` reader - This bit is set when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx1024tmaxoctgbfisR = crate::BitReader<Rx1024tmaxoctgbfis>;
impl Rx1024tmaxoctgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx1024tmaxoctgbfis {
        match self.bits {
            false => Rx1024tmaxoctgbfis::Inactive,
            true => Rx1024tmaxoctgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rx1024tmaxoctgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rx1024tmaxoctgbfis::Active
    }
}
#[doc = "Field `rx1024tmaxoctgbfis` writer - This bit is set when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Rx1024tmaxoctgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxunicastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxucgfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxucgfis> for bool {
    #[inline(always)]
    fn from(variant: Rxucgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxucgfis` reader - This bit is set when the rxunicastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type RxucgfisR = crate::BitReader<Rxucgfis>;
impl RxucgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxucgfis {
        match self.bits {
            false => Rxucgfis::Inactive,
            true => Rxucgfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxucgfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxucgfis::Active
    }
}
#[doc = "Field `rxucgfis` writer - This bit is set when the rxunicastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type RxucgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxlengtherror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxlenerfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxlenerfis> for bool {
    #[inline(always)]
    fn from(variant: Rxlenerfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxlenerfis` reader - This bit is set when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
pub type RxlenerfisR = crate::BitReader<Rxlenerfis>;
impl RxlenerfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxlenerfis {
        match self.bits {
            false => Rxlenerfis::Inactive,
            true => Rxlenerfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxlenerfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxlenerfis::Active
    }
}
#[doc = "Field `rxlenerfis` writer - This bit is set when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
pub type RxlenerfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxoutofrangetype counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxorangefis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxorangefis> for bool {
    #[inline(always)]
    fn from(variant: Rxorangefis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxorangefis` reader - This bit is set when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
pub type RxorangefisR = crate::BitReader<Rxorangefis>;
impl RxorangefisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxorangefis {
        match self.bits {
            false => Rxorangefis::Inactive,
            true => Rxorangefis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxorangefis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxorangefis::Active
    }
}
#[doc = "Field `rxorangefis` writer - This bit is set when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
pub type RxorangefisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxpauseframe counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxpausfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxpausfis> for bool {
    #[inline(always)]
    fn from(variant: Rxpausfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxpausfis` reader - This bit is set when the rxpauseframe counter reaches half of the maximum value or the maximum value."]
pub type RxpausfisR = crate::BitReader<Rxpausfis>;
impl RxpausfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxpausfis {
        match self.bits {
            false => Rxpausfis::Inactive,
            true => Rxpausfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxpausfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxpausfis::Active
    }
}
#[doc = "Field `rxpausfis` writer - This bit is set when the rxpauseframe counter reaches half of the maximum value or the maximum value."]
pub type RxpausfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxfifooverflow counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfovfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxfovfis> for bool {
    #[inline(always)]
    fn from(variant: Rxfovfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfovfis` reader - This bit is set when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
pub type RxfovfisR = crate::BitReader<Rxfovfis>;
impl RxfovfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfovfis {
        match self.bits {
            false => Rxfovfis::Inactive,
            true => Rxfovfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxfovfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxfovfis::Active
    }
}
#[doc = "Field `rxfovfis` writer - This bit is set when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
pub type RxfovfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxvlangbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxvlangbfis> for bool {
    #[inline(always)]
    fn from(variant: Rxvlangbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxvlangbfis` reader - This bit is set when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
pub type RxvlangbfisR = crate::BitReader<Rxvlangbfis>;
impl RxvlangbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxvlangbfis {
        match self.bits {
            false => Rxvlangbfis::Inactive,
            true => Rxvlangbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxvlangbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxvlangbfis::Active
    }
}
#[doc = "Field `rxvlangbfis` writer - This bit is set when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
pub type RxvlangbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxwatchdogerror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxwdogfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxwdogfis> for bool {
    #[inline(always)]
    fn from(variant: Rxwdogfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxwdogfis` reader - This bit is set when the rxwatchdogerror counter reaches half of the maximum value or the maximum value."]
pub type RxwdogfisR = crate::BitReader<Rxwdogfis>;
impl RxwdogfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxwdogfis {
        match self.bits {
            false => Rxwdogfis::Inactive,
            true => Rxwdogfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxwdogfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxwdogfis::Active
    }
}
#[doc = "Field `rxwdogfis` writer - This bit is set when the rxwatchdogerror counter reaches half of the maximum value or the maximum value."]
pub type RxwdogfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rxrcverrfis` reader - This bit is set when the rxrcverror counter reaches half of the maximum value or the maximum value."]
pub type RxrcverrfisR = crate::BitReader;
#[doc = "Field `rxrcverrfis` writer - This bit is set when the rxrcverror counter reaches half of the maximum value or the maximum value."]
pub type RxrcverrfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rxctrlfis` reader - This bit is set when the rxctrlframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxctrlfisR = crate::BitReader;
#[doc = "Field `rxctrlfis` writer - This bit is set when the rxctrlframes_g counter reaches half of the maximum value or the maximum value."]
pub type RxctrlfisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit is set when the rxframecount_bg counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxgbfrmis(&self) -> RxgbfrmisR {
        RxgbfrmisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is set when the rxoctetcount_bg counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxgboctis(&self) -> RxgboctisR {
        RxgboctisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit is set when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxgoctis(&self) -> RxgoctisR {
        RxgoctisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is set when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxbcgfis(&self) -> RxbcgfisR {
        RxbcgfisR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxmcgfis(&self) -> RxmcgfisR {
        RxmcgfisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxcrcerfis(&self) -> RxcrcerfisR {
        RxcrcerfisR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is set when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxalgnerfis(&self) -> RxalgnerfisR {
        RxalgnerfisR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is set when the rxrunterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxruntfis(&self) -> RxruntfisR {
        RxruntfisR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is set when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxjaberfis(&self) -> RxjaberfisR {
        RxjaberfisR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is set when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxusizegfis(&self) -> RxusizegfisR {
        RxusizegfisR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit is set when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxosizegfis(&self) -> RxosizegfisR {
        RxosizegfisR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit is set when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx64octgbfis(&self) -> Rx64octgbfisR {
        Rx64octgbfisR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This is set when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx65t127octgbfis(&self) -> Rx65t127octgbfisR {
        Rx65t127octgbfisR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - This bit is set when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx128t255octgbfis(&self) -> Rx128t255octgbfisR {
        Rx128t255octgbfisR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - This bit is set when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx256t511octgbfis(&self) -> Rx256t511octgbfisR {
        Rx256t511octgbfisR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - This bit is set when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx512t1023octgbfis(&self) -> Rx512t1023octgbfisR {
        Rx512t1023octgbfisR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - This bit is set when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rx1024tmaxoctgbfis(&self) -> Rx1024tmaxoctgbfisR {
        Rx1024tmaxoctgbfisR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - This bit is set when the rxunicastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxucgfis(&self) -> RxucgfisR {
        RxucgfisR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - This bit is set when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxlenerfis(&self) -> RxlenerfisR {
        RxlenerfisR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - This bit is set when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxorangefis(&self) -> RxorangefisR {
        RxorangefisR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - This bit is set when the rxpauseframe counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxpausfis(&self) -> RxpausfisR {
        RxpausfisR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - This bit is set when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxfovfis(&self) -> RxfovfisR {
        RxfovfisR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - This bit is set when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxvlangbfis(&self) -> RxvlangbfisR {
        RxvlangbfisR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - This bit is set when the rxwatchdogerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxwdogfis(&self) -> RxwdogfisR {
        RxwdogfisR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - This bit is set when the rxrcverror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxrcverrfis(&self) -> RxrcverrfisR {
        RxrcverrfisR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - This bit is set when the rxctrlframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxctrlfis(&self) -> RxctrlfisR {
        RxctrlfisR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set when the rxframecount_bg counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxgbfrmis(&mut self) -> RxgbfrmisW<GmacgrpMmcReceiveInterruptSpec> {
        RxgbfrmisW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is set when the rxoctetcount_bg counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxgboctis(&mut self) -> RxgboctisW<GmacgrpMmcReceiveInterruptSpec> {
        RxgboctisW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit is set when the rxoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxgoctis(&mut self) -> RxgoctisW<GmacgrpMmcReceiveInterruptSpec> {
        RxgoctisW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is set when the rxbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxbcgfis(&mut self) -> RxbcgfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxbcgfisW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is set when the rxmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxmcgfis(&mut self) -> RxmcgfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxmcgfisW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set when the rxcrcerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxcrcerfis(&mut self) -> RxcrcerfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxcrcerfisW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is set when the rxalignmenterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxalgnerfis(&mut self) -> RxalgnerfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxalgnerfisW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is set when the rxrunterror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxruntfis(&mut self) -> RxruntfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxruntfisW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is set when the rxjabbererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxjaberfis(&mut self) -> RxjaberfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxjaberfisW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is set when the rxundersize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxusizegfis(&mut self) -> RxusizegfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxusizegfisW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit is set when the rxoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxosizegfis(&mut self) -> RxosizegfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxosizegfisW::new(self, 10)
    }
    #[doc = "Bit 11 - This bit is set when the rx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx64octgbfis(&mut self) -> Rx64octgbfisW<GmacgrpMmcReceiveInterruptSpec> {
        Rx64octgbfisW::new(self, 11)
    }
    #[doc = "Bit 12 - This is set when the rx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx65t127octgbfis(&mut self) -> Rx65t127octgbfisW<GmacgrpMmcReceiveInterruptSpec> {
        Rx65t127octgbfisW::new(self, 12)
    }
    #[doc = "Bit 13 - This bit is set when the rx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx128t255octgbfis(&mut self) -> Rx128t255octgbfisW<GmacgrpMmcReceiveInterruptSpec> {
        Rx128t255octgbfisW::new(self, 13)
    }
    #[doc = "Bit 14 - This bit is set when the rx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx256t511octgbfis(&mut self) -> Rx256t511octgbfisW<GmacgrpMmcReceiveInterruptSpec> {
        Rx256t511octgbfisW::new(self, 14)
    }
    #[doc = "Bit 15 - This bit is set when the rx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx512t1023octgbfis(&mut self) -> Rx512t1023octgbfisW<GmacgrpMmcReceiveInterruptSpec> {
        Rx512t1023octgbfisW::new(self, 15)
    }
    #[doc = "Bit 16 - This bit is set when the rx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rx1024tmaxoctgbfis(&mut self) -> Rx1024tmaxoctgbfisW<GmacgrpMmcReceiveInterruptSpec> {
        Rx1024tmaxoctgbfisW::new(self, 16)
    }
    #[doc = "Bit 17 - This bit is set when the rxunicastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxucgfis(&mut self) -> RxucgfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxucgfisW::new(self, 17)
    }
    #[doc = "Bit 18 - This bit is set when the rxlengtherror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxlenerfis(&mut self) -> RxlenerfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxlenerfisW::new(self, 18)
    }
    #[doc = "Bit 19 - This bit is set when the rxoutofrangetype counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxorangefis(&mut self) -> RxorangefisW<GmacgrpMmcReceiveInterruptSpec> {
        RxorangefisW::new(self, 19)
    }
    #[doc = "Bit 20 - This bit is set when the rxpauseframe counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxpausfis(&mut self) -> RxpausfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxpausfisW::new(self, 20)
    }
    #[doc = "Bit 21 - This bit is set when the rxfifooverflow counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxfovfis(&mut self) -> RxfovfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxfovfisW::new(self, 21)
    }
    #[doc = "Bit 22 - This bit is set when the rxvlanframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxvlangbfis(&mut self) -> RxvlangbfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxvlangbfisW::new(self, 22)
    }
    #[doc = "Bit 23 - This bit is set when the rxwatchdogerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxwdogfis(&mut self) -> RxwdogfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxwdogfisW::new(self, 23)
    }
    #[doc = "Bit 24 - This bit is set when the rxrcverror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxrcverrfis(&mut self) -> RxrcverrfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxrcverrfisW::new(self, 24)
    }
    #[doc = "Bit 25 - This bit is set when the rxctrlframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxctrlfis(&mut self) -> RxctrlfisW<GmacgrpMmcReceiveInterruptSpec> {
        RxctrlfisW::new(self, 25)
    }
}
#[doc = "The MMC Receive Interrupt register maintains the interrupts that are generated when the following happens: * Receive statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter). * Receive statistic counters cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When the Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_receive_interrupt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcReceiveInterruptSpec;
impl crate::RegisterSpec for GmacgrpMmcReceiveInterruptSpec {
    type Ux = u32;
    const OFFSET: u64 = 260u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_receive_interrupt::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcReceiveInterruptSpec {}
#[doc = "`reset()` method sets gmacgrp_MMC_Receive_Interrupt to value 0"]
impl crate::Resettable for GmacgrpMmcReceiveInterruptSpec {
    const RESET_VALUE: u32 = 0;
}
