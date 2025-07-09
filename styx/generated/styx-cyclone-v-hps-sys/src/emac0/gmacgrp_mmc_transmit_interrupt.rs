// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MMC_Transmit_Interrupt` reader"]
pub type R = crate::R<GmacgrpMmcTransmitInterruptSpec>;
#[doc = "Register `gmacgrp_MMC_Transmit_Interrupt` writer"]
pub type W = crate::W<GmacgrpMmcTransmitInterruptSpec>;
#[doc = "This bit is set when the txoctetcount_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgboctis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txgboctis> for bool {
    #[inline(always)]
    fn from(variant: Txgboctis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgboctis` reader - This bit is set when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgboctisR = crate::BitReader<Txgboctis>;
impl TxgboctisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgboctis {
        match self.bits {
            false => Txgboctis::Inactive,
            true => Txgboctis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txgboctis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txgboctis::Active
    }
}
#[doc = "Field `txgboctis` writer - This bit is set when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgboctisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txframecount_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgbfrmis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txgbfrmis> for bool {
    #[inline(always)]
    fn from(variant: Txgbfrmis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgbfrmis` reader - This bit is set when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgbfrmisR = crate::BitReader<Txgbfrmis>;
impl TxgbfrmisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgbfrmis {
        match self.bits {
            false => Txgbfrmis::Inactive,
            true => Txgbfrmis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txgbfrmis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txgbfrmis::Active
    }
}
#[doc = "Field `txgbfrmis` writer - This bit is set when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
pub type TxgbfrmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txbcgfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txbcgfis> for bool {
    #[inline(always)]
    fn from(variant: Txbcgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txbcgfis` reader - This bit is set when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxbcgfisR = crate::BitReader<Txbcgfis>;
impl TxbcgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txbcgfis {
        match self.bits {
            false => Txbcgfis::Inactive,
            true => Txbcgfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txbcgfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txbcgfis::Active
    }
}
#[doc = "Field `txbcgfis` writer - This bit is set when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxbcgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txmulticastframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txmcgfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txmcgfis> for bool {
    #[inline(always)]
    fn from(variant: Txmcgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txmcgfis` reader - This bit is set when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcgfisR = crate::BitReader<Txmcgfis>;
impl TxmcgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txmcgfis {
        match self.bits {
            false => Txmcgfis::Inactive,
            true => Txmcgfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txmcgfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txmcgfis::Active
    }
}
#[doc = "Field `txmcgfis` writer - This bit is set when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the tx64octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx64octgbfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tx64octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Tx64octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx64octgbfis` reader - This bit is set when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx64octgbfisR = crate::BitReader<Tx64octgbfis>;
impl Tx64octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx64octgbfis {
        match self.bits {
            false => Tx64octgbfis::Disabled,
            true => Tx64octgbfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tx64octgbfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tx64octgbfis::Enabled
    }
}
#[doc = "Field `tx64octgbfis` writer - This bit is set when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx64octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx65t127octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tx65t127octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Tx65t127octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx65t127octgbfis` reader - This bit is set when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx65t127octgbfisR = crate::BitReader<Tx65t127octgbfis>;
impl Tx65t127octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx65t127octgbfis {
        match self.bits {
            false => Tx65t127octgbfis::Inactive,
            true => Tx65t127octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tx65t127octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tx65t127octgbfis::Active
    }
}
#[doc = "Field `tx65t127octgbfis` writer - This bit is set when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx65t127octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx128t255octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tx128t255octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Tx128t255octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx128t255octgbfis` reader - This bit is set when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx128t255octgbfisR = crate::BitReader<Tx128t255octgbfis>;
impl Tx128t255octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx128t255octgbfis {
        match self.bits {
            false => Tx128t255octgbfis::Inactive,
            true => Tx128t255octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tx128t255octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tx128t255octgbfis::Active
    }
}
#[doc = "Field `tx128t255octgbfis` writer - This bit is set when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx128t255octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx256t511octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tx256t511octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Tx256t511octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx256t511octgbfis` reader - This bit is set when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx256t511octgbfisR = crate::BitReader<Tx256t511octgbfis>;
impl Tx256t511octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx256t511octgbfis {
        match self.bits {
            false => Tx256t511octgbfis::Inactive,
            true => Tx256t511octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tx256t511octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tx256t511octgbfis::Active
    }
}
#[doc = "Field `tx256t511octgbfis` writer - This bit is set when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx256t511octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx512t1023octgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tx512t1023octgbfis> for bool {
    #[inline(always)]
    fn from(variant: Tx512t1023octgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx512t1023octgbfis` reader - This bit is set when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx512t1023octgbfisR = crate::BitReader<Tx512t1023octgbfis>;
impl Tx512t1023octgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx512t1023octgbfis {
        match self.bits {
            false => Tx512t1023octgbfis::Inactive,
            true => Tx512t1023octgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tx512t1023octgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tx512t1023octgbfis::Active
    }
}
#[doc = "Field `tx512t1023octgbfis` writer - This bit is set when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx512t1023octgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx1024tmaxoctgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tx1024tmaxoctgbfis> for bool {
    #[inline(always)]
    fn from(variant: Tx1024tmaxoctgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tx1024tmaxoctgbfis` reader - This bit is set when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx1024tmaxoctgbfisR = crate::BitReader<Tx1024tmaxoctgbfis>;
impl Tx1024tmaxoctgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx1024tmaxoctgbfis {
        match self.bits {
            false => Tx1024tmaxoctgbfis::Inactive,
            true => Tx1024tmaxoctgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tx1024tmaxoctgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tx1024tmaxoctgbfis::Active
    }
}
#[doc = "Field `tx1024tmaxoctgbfis` writer - This bit is set when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
pub type Tx1024tmaxoctgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txunicastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txucgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txucgbfis> for bool {
    #[inline(always)]
    fn from(variant: Txucgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txucgbfis` reader - This bit is set when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxucgbfisR = crate::BitReader<Txucgbfis>;
impl TxucgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txucgbfis {
        match self.bits {
            false => Txucgbfis::Inactive,
            true => Txucgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txucgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txucgbfis::Active
    }
}
#[doc = "Field `txucgbfis` writer - This bit is set when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxucgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txmcgbfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txmcgbfis> for bool {
    #[inline(always)]
    fn from(variant: Txmcgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txmcgbfis` reader - This bit is set when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxmcgbfisR = crate::BitReader<Txmcgbfis>;
impl TxmcgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txmcgbfis {
        match self.bits {
            false => Txmcgbfis::Inactive,
            true => Txmcgbfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txmcgbfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txmcgbfis::Active
    }
}
#[doc = "Field `txmcgbfis` writer - This bit is set when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxmcgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txbcgbfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txbcgbfis> for bool {
    #[inline(always)]
    fn from(variant: Txbcgbfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txbcgbfis` reader - This bit is set when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxbcgbfisR = crate::BitReader<Txbcgbfis>;
impl TxbcgbfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txbcgbfis {
        match self.bits {
            false => Txbcgbfis::Disabled,
            true => Txbcgbfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txbcgbfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txbcgbfis::Enabled
    }
}
#[doc = "Field `txbcgbfis` writer - This bit is set when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
pub type TxbcgbfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txunderflowerror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txuflowerfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txuflowerfis> for bool {
    #[inline(always)]
    fn from(variant: Txuflowerfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txuflowerfis` reader - This bit is set when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
pub type TxuflowerfisR = crate::BitReader<Txuflowerfis>;
impl TxuflowerfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txuflowerfis {
        match self.bits {
            false => Txuflowerfis::Disabled,
            true => Txuflowerfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txuflowerfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txuflowerfis::Enabled
    }
}
#[doc = "Field `txuflowerfis` writer - This bit is set when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
pub type TxuflowerfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txsinglecol_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txscolgfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txscolgfis> for bool {
    #[inline(always)]
    fn from(variant: Txscolgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txscolgfis` reader - This bit is set when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
pub type TxscolgfisR = crate::BitReader<Txscolgfis>;
impl TxscolgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txscolgfis {
        match self.bits {
            false => Txscolgfis::Disabled,
            true => Txscolgfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txscolgfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txscolgfis::Enabled
    }
}
#[doc = "Field `txscolgfis` writer - This bit is set when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
pub type TxscolgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txmulticol_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txmcolgfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txmcolgfis> for bool {
    #[inline(always)]
    fn from(variant: Txmcolgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txmcolgfis` reader - This bit is set when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcolgfisR = crate::BitReader<Txmcolgfis>;
impl TxmcolgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txmcolgfis {
        match self.bits {
            false => Txmcolgfis::Disabled,
            true => Txmcolgfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txmcolgfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txmcolgfis::Enabled
    }
}
#[doc = "Field `txmcolgfis` writer - This bit is set when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
pub type TxmcolgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txdeferred counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txdeffis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txdeffis> for bool {
    #[inline(always)]
    fn from(variant: Txdeffis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txdeffis` reader - This bit is set when the txdeferred counter reaches half of the maximum value or the maximum value."]
pub type TxdeffisR = crate::BitReader<Txdeffis>;
impl TxdeffisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txdeffis {
        match self.bits {
            false => Txdeffis::Disabled,
            true => Txdeffis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txdeffis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txdeffis::Enabled
    }
}
#[doc = "Field `txdeffis` writer - This bit is set when the txdeferred counter reaches half of the maximum value or the maximum value."]
pub type TxdeffisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txlatecol counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txlatcolfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txlatcolfis> for bool {
    #[inline(always)]
    fn from(variant: Txlatcolfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txlatcolfis` reader - This bit is set when the txlatecol counter reaches half of the maximum value or the maximum value."]
pub type TxlatcolfisR = crate::BitReader<Txlatcolfis>;
impl TxlatcolfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txlatcolfis {
        match self.bits {
            false => Txlatcolfis::Disabled,
            true => Txlatcolfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txlatcolfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txlatcolfis::Enabled
    }
}
#[doc = "Field `txlatcolfis` writer - This bit is set when the txlatecol counter reaches half of the maximum value or the maximum value."]
pub type TxlatcolfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txexcesscol counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txexcolfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txexcolfis> for bool {
    #[inline(always)]
    fn from(variant: Txexcolfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txexcolfis` reader - This bit is set when the txexcesscol counter reaches half of the maximum value or the maximum value."]
pub type TxexcolfisR = crate::BitReader<Txexcolfis>;
impl TxexcolfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txexcolfis {
        match self.bits {
            false => Txexcolfis::Disabled,
            true => Txexcolfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txexcolfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txexcolfis::Enabled
    }
}
#[doc = "Field `txexcolfis` writer - This bit is set when the txexcesscol counter reaches half of the maximum value or the maximum value."]
pub type TxexcolfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txcarriererror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txcarerfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txcarerfis> for bool {
    #[inline(always)]
    fn from(variant: Txcarerfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txcarerfis` reader - This bit is set when the txcarriererror counter reaches half of the maximum value or the maximum value."]
pub type TxcarerfisR = crate::BitReader<Txcarerfis>;
impl TxcarerfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txcarerfis {
        match self.bits {
            false => Txcarerfis::Disabled,
            true => Txcarerfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txcarerfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txcarerfis::Enabled
    }
}
#[doc = "Field `txcarerfis` writer - This bit is set when the txcarriererror counter reaches half of the maximum value or the maximum value."]
pub type TxcarerfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txoctetcount_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgoctis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txgoctis> for bool {
    #[inline(always)]
    fn from(variant: Txgoctis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgoctis` reader - This bit is set when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgoctisR = crate::BitReader<Txgoctis>;
impl TxgoctisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgoctis {
        match self.bits {
            false => Txgoctis::Disabled,
            true => Txgoctis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txgoctis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txgoctis::Enabled
    }
}
#[doc = "Field `txgoctis` writer - This bit is set when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgoctisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txframecount_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txgfrmis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txgfrmis> for bool {
    #[inline(always)]
    fn from(variant: Txgfrmis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txgfrmis` reader - This bit is set when the txframecount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgfrmisR = crate::BitReader<Txgfrmis>;
impl TxgfrmisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txgfrmis {
        match self.bits {
            false => Txgfrmis::Disabled,
            true => Txgfrmis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txgfrmis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txgfrmis::Enabled
    }
}
#[doc = "Field `txgfrmis` writer - This bit is set when the txframecount_g counter reaches half of the maximum value or the maximum value."]
pub type TxgfrmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txexcessdef counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txexdeffis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txexdeffis> for bool {
    #[inline(always)]
    fn from(variant: Txexdeffis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txexdeffis` reader - This bit is set when the txexcessdef counter reaches half of the maximum value or the maximum value."]
pub type TxexdeffisR = crate::BitReader<Txexdeffis>;
impl TxexdeffisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txexdeffis {
        match self.bits {
            false => Txexdeffis::Disabled,
            true => Txexdeffis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txexdeffis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txexdeffis::Enabled
    }
}
#[doc = "Field `txexdeffis` writer - This bit is set when the txexcessdef counter reaches half of the maximum value or the maximum value."]
pub type TxexdeffisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txpauseframeserror counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txpausfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txpausfis> for bool {
    #[inline(always)]
    fn from(variant: Txpausfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txpausfis` reader - This bit is set when the txpauseframeserror counter reaches half of the maximum value or the maximum value."]
pub type TxpausfisR = crate::BitReader<Txpausfis>;
impl TxpausfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txpausfis {
        match self.bits {
            false => Txpausfis::Disabled,
            true => Txpausfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txpausfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txpausfis::Enabled
    }
}
#[doc = "Field `txpausfis` writer - This bit is set when the txpauseframeserror counter reaches half of the maximum value or the maximum value."]
pub type TxpausfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the txvlanframes_g counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txvlangfis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txvlangfis> for bool {
    #[inline(always)]
    fn from(variant: Txvlangfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txvlangfis` reader - This bit is set when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxvlangfisR = crate::BitReader<Txvlangfis>;
impl TxvlangfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txvlangfis {
        match self.bits {
            false => Txvlangfis::Disabled,
            true => Txvlangfis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txvlangfis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txvlangfis::Enabled
    }
}
#[doc = "Field `txvlangfis` writer - This bit is set when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
pub type TxvlangfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `txosizegfis` reader - This bit is set when the txoversize_g counter reaches half of the maximum value or the maximum value."]
pub type TxosizegfisR = crate::BitReader;
#[doc = "Field `txosizegfis` writer - This bit is set when the txoversize_g counter reaches half of the maximum value or the maximum value."]
pub type TxosizegfisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit is set when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgboctis(&self) -> TxgboctisR {
        TxgboctisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is set when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgbfrmis(&self) -> TxgbfrmisR {
        TxgbfrmisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit is set when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txbcgfis(&self) -> TxbcgfisR {
        TxbcgfisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is set when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txmcgfis(&self) -> TxmcgfisR {
        TxmcgfisR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx64octgbfis(&self) -> Tx64octgbfisR {
        Tx64octgbfisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx65t127octgbfis(&self) -> Tx65t127octgbfisR {
        Tx65t127octgbfisR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is set when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx128t255octgbfis(&self) -> Tx128t255octgbfisR {
        Tx128t255octgbfisR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is set when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx256t511octgbfis(&self) -> Tx256t511octgbfisR {
        Tx256t511octgbfisR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is set when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx512t1023octgbfis(&self) -> Tx512t1023octgbfisR {
        Tx512t1023octgbfisR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is set when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn tx1024tmaxoctgbfis(&self) -> Tx1024tmaxoctgbfisR {
        Tx1024tmaxoctgbfisR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit is set when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txucgbfis(&self) -> TxucgbfisR {
        TxucgbfisR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit is set when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txmcgbfis(&self) -> TxmcgbfisR {
        TxmcgbfisR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit is set when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txbcgbfis(&self) -> TxbcgbfisR {
        TxbcgbfisR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - This bit is set when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txuflowerfis(&self) -> TxuflowerfisR {
        TxuflowerfisR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - This bit is set when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txscolgfis(&self) -> TxscolgfisR {
        TxscolgfisR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - This bit is set when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txmcolgfis(&self) -> TxmcolgfisR {
        TxmcolgfisR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - This bit is set when the txdeferred counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txdeffis(&self) -> TxdeffisR {
        TxdeffisR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - This bit is set when the txlatecol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txlatcolfis(&self) -> TxlatcolfisR {
        TxlatcolfisR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - This bit is set when the txexcesscol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txexcolfis(&self) -> TxexcolfisR {
        TxexcolfisR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - This bit is set when the txcarriererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txcarerfis(&self) -> TxcarerfisR {
        TxcarerfisR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - This bit is set when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgoctis(&self) -> TxgoctisR {
        TxgoctisR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - This bit is set when the txframecount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txgfrmis(&self) -> TxgfrmisR {
        TxgfrmisR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - This bit is set when the txexcessdef counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txexdeffis(&self) -> TxexdeffisR {
        TxexdeffisR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - This bit is set when the txpauseframeserror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txpausfis(&self) -> TxpausfisR {
        TxpausfisR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - This bit is set when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txvlangfis(&self) -> TxvlangfisR {
        TxvlangfisR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - This bit is set when the txoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn txosizegfis(&self) -> TxosizegfisR {
        TxosizegfisR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set when the txoctetcount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgboctis(&mut self) -> TxgboctisW<GmacgrpMmcTransmitInterruptSpec> {
        TxgboctisW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is set when the txframecount_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgbfrmis(&mut self) -> TxgbfrmisW<GmacgrpMmcTransmitInterruptSpec> {
        TxgbfrmisW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit is set when the txbroadcastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txbcgfis(&mut self) -> TxbcgfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxbcgfisW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is set when the txmulticastframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txmcgfis(&mut self) -> TxmcgfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxmcgfisW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is set when the tx64octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx64octgbfis(&mut self) -> Tx64octgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        Tx64octgbfisW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set when the tx65to127octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx65t127octgbfis(&mut self) -> Tx65t127octgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        Tx65t127octgbfisW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is set when the tx128to255octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx128t255octgbfis(&mut self) -> Tx128t255octgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        Tx128t255octgbfisW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is set when the tx256to511octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx256t511octgbfis(&mut self) -> Tx256t511octgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        Tx256t511octgbfisW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is set when the tx512to1023octets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx512t1023octgbfis(&mut self) -> Tx512t1023octgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        Tx512t1023octgbfisW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is set when the tx1024tomaxoctets_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn tx1024tmaxoctgbfis(&mut self) -> Tx1024tmaxoctgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        Tx1024tmaxoctgbfisW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit is set when the txunicastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txucgbfis(&mut self) -> TxucgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxucgbfisW::new(self, 10)
    }
    #[doc = "Bit 11 - This bit is set when the txmulticastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txmcgbfis(&mut self) -> TxmcgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxmcgbfisW::new(self, 11)
    }
    #[doc = "Bit 12 - This bit is set when the txbroadcastframes_gb counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txbcgbfis(&mut self) -> TxbcgbfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxbcgbfisW::new(self, 12)
    }
    #[doc = "Bit 13 - This bit is set when the txunderflowerror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txuflowerfis(&mut self) -> TxuflowerfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxuflowerfisW::new(self, 13)
    }
    #[doc = "Bit 14 - This bit is set when the txsinglecol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txscolgfis(&mut self) -> TxscolgfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxscolgfisW::new(self, 14)
    }
    #[doc = "Bit 15 - This bit is set when the txmulticol_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txmcolgfis(&mut self) -> TxmcolgfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxmcolgfisW::new(self, 15)
    }
    #[doc = "Bit 16 - This bit is set when the txdeferred counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txdeffis(&mut self) -> TxdeffisW<GmacgrpMmcTransmitInterruptSpec> {
        TxdeffisW::new(self, 16)
    }
    #[doc = "Bit 17 - This bit is set when the txlatecol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txlatcolfis(&mut self) -> TxlatcolfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxlatcolfisW::new(self, 17)
    }
    #[doc = "Bit 18 - This bit is set when the txexcesscol counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txexcolfis(&mut self) -> TxexcolfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxexcolfisW::new(self, 18)
    }
    #[doc = "Bit 19 - This bit is set when the txcarriererror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txcarerfis(&mut self) -> TxcarerfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxcarerfisW::new(self, 19)
    }
    #[doc = "Bit 20 - This bit is set when the txoctetcount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgoctis(&mut self) -> TxgoctisW<GmacgrpMmcTransmitInterruptSpec> {
        TxgoctisW::new(self, 20)
    }
    #[doc = "Bit 21 - This bit is set when the txframecount_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txgfrmis(&mut self) -> TxgfrmisW<GmacgrpMmcTransmitInterruptSpec> {
        TxgfrmisW::new(self, 21)
    }
    #[doc = "Bit 22 - This bit is set when the txexcessdef counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txexdeffis(&mut self) -> TxexdeffisW<GmacgrpMmcTransmitInterruptSpec> {
        TxexdeffisW::new(self, 22)
    }
    #[doc = "Bit 23 - This bit is set when the txpauseframeserror counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txpausfis(&mut self) -> TxpausfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxpausfisW::new(self, 23)
    }
    #[doc = "Bit 24 - This bit is set when the txvlanframes_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txvlangfis(&mut self) -> TxvlangfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxvlangfisW::new(self, 24)
    }
    #[doc = "Bit 25 - This bit is set when the txoversize_g counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn txosizegfis(&mut self) -> TxosizegfisW<GmacgrpMmcTransmitInterruptSpec> {
        TxosizegfisW::new(self, 25)
    }
}
#[doc = "The MMC Transmit Interrupt register maintains the interrupts generated when transmit statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and the maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Transmit Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_transmit_interrupt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcTransmitInterruptSpec;
impl crate::RegisterSpec for GmacgrpMmcTransmitInterruptSpec {
    type Ux = u32;
    const OFFSET: u64 = 264u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_transmit_interrupt::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcTransmitInterruptSpec {}
#[doc = "`reset()` method sets gmacgrp_MMC_Transmit_Interrupt to value 0"]
impl crate::Resettable for GmacgrpMmcTransmitInterruptSpec {
    const RESET_VALUE: u32 = 0;
}
