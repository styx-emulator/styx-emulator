// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_HW_Feature` reader"]
pub type R = crate::R<DmagrpHwFeatureSpec>;
#[doc = "Register `dmagrp_HW_Feature` writer"]
pub type W = crate::W<DmagrpHwFeatureSpec>;
#[doc = "10/100 Mbps support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miisel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Miisel> for bool {
    #[inline(always)]
    fn from(variant: Miisel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `miisel` reader - 10/100 Mbps support"]
pub type MiiselR = crate::BitReader<Miisel>;
impl MiiselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Miisel {
        match self.bits {
            false => Miisel::Disabled,
            true => Miisel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Miisel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Miisel::Enabled
    }
}
#[doc = "Field `miisel` writer - 10/100 Mbps support"]
pub type MiiselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "1000 Mbps support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gmiisel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Gmiisel> for bool {
    #[inline(always)]
    fn from(variant: Gmiisel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gmiisel` reader - 1000 Mbps support"]
pub type GmiiselR = crate::BitReader<Gmiisel>;
impl GmiiselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gmiisel {
        match self.bits {
            false => Gmiisel::Disabled,
            true => Gmiisel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Gmiisel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Gmiisel::Enabled
    }
}
#[doc = "Field `gmiisel` writer - 1000 Mbps support"]
pub type GmiiselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Half-Duplex support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hdsel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hdsel> for bool {
    #[inline(always)]
    fn from(variant: Hdsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hdsel` reader - Half-Duplex support"]
pub type HdselR = crate::BitReader<Hdsel>;
impl HdselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hdsel {
        match self.bits {
            false => Hdsel::Disabled,
            true => Hdsel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hdsel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hdsel::Enabled
    }
}
#[doc = "Field `hdsel` writer - Half-Duplex support"]
pub type HdselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "HASH Filter support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hashsel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hashsel> for bool {
    #[inline(always)]
    fn from(variant: Hashsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hashsel` reader - HASH Filter support"]
pub type HashselR = crate::BitReader<Hashsel>;
impl HashselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hashsel {
        match self.bits {
            false => Hashsel::Disabled,
            true => Hashsel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hashsel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hashsel::Enabled
    }
}
#[doc = "Field `hashsel` writer - HASH Filter support"]
pub type HashselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Multiple MAC Address Registers support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addmacadrsel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Addmacadrsel> for bool {
    #[inline(always)]
    fn from(variant: Addmacadrsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `addmacadrsel` reader - Multiple MAC Address Registers support"]
pub type AddmacadrselR = crate::BitReader<Addmacadrsel>;
impl AddmacadrselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Addmacadrsel {
        match self.bits {
            false => Addmacadrsel::Disabled,
            true => Addmacadrsel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Addmacadrsel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Addmacadrsel::Enabled
    }
}
#[doc = "Field `addmacadrsel` writer - Multiple MAC Address Registers support"]
pub type AddmacadrselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "TBI/SGMII/RTBI PHY interface support\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pcssel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Pcssel> for bool {
    #[inline(always)]
    fn from(variant: Pcssel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pcssel` reader - TBI/SGMII/RTBI PHY interface support"]
pub type PcsselR = crate::BitReader<Pcssel>;
impl PcsselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pcssel {
        match self.bits {
            false => Pcssel::Disabled,
            true => Pcssel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Pcssel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Pcssel::Enabled
    }
}
#[doc = "Field `pcssel` writer - TBI/SGMII/RTBI PHY interface support"]
pub type PcsselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "SMA (MDIO) Interface support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Smasel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Smasel> for bool {
    #[inline(always)]
    fn from(variant: Smasel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `smasel` reader - SMA (MDIO) Interface support"]
pub type SmaselR = crate::BitReader<Smasel>;
impl SmaselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Smasel {
        match self.bits {
            false => Smasel::Disabled,
            true => Smasel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Smasel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Smasel::Enabled
    }
}
#[doc = "Field `smasel` writer - SMA (MDIO) Interface support"]
pub type SmaselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "PMT Remote Wakeup support\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rwksel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rwksel> for bool {
    #[inline(always)]
    fn from(variant: Rwksel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rwksel` reader - PMT Remote Wakeup support"]
pub type RwkselR = crate::BitReader<Rwksel>;
impl RwkselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rwksel {
        match self.bits {
            false => Rwksel::Disabled,
            true => Rwksel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rwksel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rwksel::Enabled
    }
}
#[doc = "Field `rwksel` writer - PMT Remote Wakeup support"]
pub type RwkselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "PMT Magic Packet\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mgksel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Mgksel> for bool {
    #[inline(always)]
    fn from(variant: Mgksel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mgksel` reader - PMT Magic Packet"]
pub type MgkselR = crate::BitReader<Mgksel>;
impl MgkselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mgksel {
        match self.bits {
            false => Mgksel::Disabled,
            true => Mgksel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Mgksel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Mgksel::Enabled
    }
}
#[doc = "Field `mgksel` writer - PMT Magic Packet"]
pub type MgkselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "RMON block\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mmcsel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Mmcsel> for bool {
    #[inline(always)]
    fn from(variant: Mmcsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mmcsel` reader - RMON block"]
pub type MmcselR = crate::BitReader<Mmcsel>;
impl MmcselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mmcsel {
        match self.bits {
            false => Mmcsel::Disabled,
            true => Mmcsel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Mmcsel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Mmcsel::Enabled
    }
}
#[doc = "Field `mmcsel` writer - RMON block"]
pub type MmcselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Only IEEE 1588-2002 Timestamp\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsver1sel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsver1sel> for bool {
    #[inline(always)]
    fn from(variant: Tsver1sel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsver1sel` reader - Only IEEE 1588-2002 Timestamp"]
pub type Tsver1selR = crate::BitReader<Tsver1sel>;
impl Tsver1selR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsver1sel {
        match self.bits {
            false => Tsver1sel::Disabled,
            true => Tsver1sel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsver1sel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsver1sel::Enabled
    }
}
#[doc = "Field `tsver1sel` writer - Only IEEE 1588-2002 Timestamp"]
pub type Tsver1selW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "IEEE 1588-2008 Advanced Timestamp\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsver2sel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsver2sel> for bool {
    #[inline(always)]
    fn from(variant: Tsver2sel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsver2sel` reader - IEEE 1588-2008 Advanced Timestamp"]
pub type Tsver2selR = crate::BitReader<Tsver2sel>;
impl Tsver2selR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsver2sel {
        match self.bits {
            false => Tsver2sel::Disabled,
            true => Tsver2sel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsver2sel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsver2sel::Enabled
    }
}
#[doc = "Field `tsver2sel` writer - IEEE 1588-2008 Advanced Timestamp"]
pub type Tsver2selW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Energy Efficient Ethernet Feature\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eeesel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Eeesel> for bool {
    #[inline(always)]
    fn from(variant: Eeesel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `eeesel` reader - Energy Efficient Ethernet Feature"]
pub type EeeselR = crate::BitReader<Eeesel>;
impl EeeselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eeesel {
        match self.bits {
            false => Eeesel::Disabled,
            true => Eeesel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Eeesel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Eeesel::Enabled
    }
}
#[doc = "Field `eeesel` writer - Energy Efficient Ethernet Feature"]
pub type EeeselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "AV Feature\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Avsel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Avsel> for bool {
    #[inline(always)]
    fn from(variant: Avsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `avsel` reader - AV Feature"]
pub type AvselR = crate::BitReader<Avsel>;
impl AvselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Avsel {
        match self.bits {
            false => Avsel::Disabled,
            true => Avsel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Avsel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Avsel::Enabled
    }
}
#[doc = "Field `avsel` writer - AV Feature"]
pub type AvselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Checksum Offload in Tx\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txoesel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txoesel> for bool {
    #[inline(always)]
    fn from(variant: Txoesel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txoesel` reader - Checksum Offload in Tx"]
pub type TxoeselR = crate::BitReader<Txoesel>;
impl TxoeselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txoesel {
        match self.bits {
            false => Txoesel::Disabled,
            true => Txoesel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txoesel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txoesel::Enabled
    }
}
#[doc = "Field `txoesel` writer - Checksum Offload in Tx"]
pub type TxoeselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "IP Checksum Offload (Type 1) in Rx\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtyp1coe {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxtyp1coe> for bool {
    #[inline(always)]
    fn from(variant: Rxtyp1coe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtyp1coe` reader - IP Checksum Offload (Type 1) in Rx"]
pub type Rxtyp1coeR = crate::BitReader<Rxtyp1coe>;
impl Rxtyp1coeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtyp1coe {
        match self.bits {
            false => Rxtyp1coe::Disabled,
            true => Rxtyp1coe::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxtyp1coe::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxtyp1coe::Enabled
    }
}
#[doc = "Field `rxtyp1coe` writer - IP Checksum Offload (Type 1) in Rx"]
pub type Rxtyp1coeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "IP Checksum Offload (Type 2) in Rx\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtyp2coe {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxtyp2coe> for bool {
    #[inline(always)]
    fn from(variant: Rxtyp2coe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtyp2coe` reader - IP Checksum Offload (Type 2) in Rx"]
pub type Rxtyp2coeR = crate::BitReader<Rxtyp2coe>;
impl Rxtyp2coeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtyp2coe {
        match self.bits {
            false => Rxtyp2coe::Disabled,
            true => Rxtyp2coe::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxtyp2coe::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxtyp2coe::Enabled
    }
}
#[doc = "Field `rxtyp2coe` writer - IP Checksum Offload (Type 2) in Rx"]
pub type Rxtyp2coeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "RxFIFO > 2048 Bytes\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfifosize {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxfifosize> for bool {
    #[inline(always)]
    fn from(variant: Rxfifosize) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfifosize` reader - RxFIFO > 2048 Bytes"]
pub type RxfifosizeR = crate::BitReader<Rxfifosize>;
impl RxfifosizeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfifosize {
        match self.bits {
            false => Rxfifosize::Disabled,
            true => Rxfifosize::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxfifosize::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxfifosize::Enabled
    }
}
#[doc = "Field `rxfifosize` writer - RxFIFO > 2048 Bytes"]
pub type RxfifosizeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Number of additional Rx channels\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rxchcnt {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxchcnt> for u8 {
    #[inline(always)]
    fn from(variant: Rxchcnt) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rxchcnt {
    type Ux = u8;
}
#[doc = "Field `rxchcnt` reader - Number of additional Rx channels"]
pub type RxchcntR = crate::FieldReader<Rxchcnt>;
impl RxchcntR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rxchcnt> {
        match self.bits {
            0 => Some(Rxchcnt::Disabled),
            1 => Some(Rxchcnt::Enabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxchcnt::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxchcnt::Enabled
    }
}
#[doc = "Field `rxchcnt` writer - Number of additional Rx channels"]
pub type RxchcntW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Number of additional Tx channels\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Txchcnt {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txchcnt> for u8 {
    #[inline(always)]
    fn from(variant: Txchcnt) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Txchcnt {
    type Ux = u8;
}
#[doc = "Field `txchcnt` reader - Number of additional Tx channels"]
pub type TxchcntR = crate::FieldReader<Txchcnt>;
impl TxchcntR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Txchcnt> {
        match self.bits {
            0 => Some(Txchcnt::Disabled),
            1 => Some(Txchcnt::Enabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txchcnt::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txchcnt::Enabled
    }
}
#[doc = "Field `txchcnt` writer - Number of additional Tx channels"]
pub type TxchcntW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Alternate (Enhanced Descriptor)\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enhdessel {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Enhdessel> for bool {
    #[inline(always)]
    fn from(variant: Enhdessel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enhdessel` reader - Alternate (Enhanced Descriptor)"]
pub type EnhdesselR = crate::BitReader<Enhdessel>;
impl EnhdesselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enhdessel {
        match self.bits {
            false => Enhdessel::Disabled,
            true => Enhdessel::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Enhdessel::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Enhdessel::Enabled
    }
}
#[doc = "Field `enhdessel` writer - Alternate (Enhanced Descriptor)"]
pub type EnhdesselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When you have multiple PHY interfaces in your configuration, this field indicates the sampled value of emacx_phy_if_selduring reset de-assertion.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Actphyif {
    #[doc = "0: `0`"]
    Gmiimii0 = 0,
    #[doc = "1: `1`"]
    Rgmii1 = 1,
    #[doc = "2: `10`"]
    Sgmii2 = 2,
    #[doc = "3: `11`"]
    Tbi3 = 3,
    #[doc = "4: `100`"]
    Rmii4 = 4,
    #[doc = "5: `101`"]
    Rtbi5 = 5,
    #[doc = "6: `110`"]
    Smii6 = 6,
    #[doc = "7: `111`"]
    Revmii7 = 7,
}
impl From<Actphyif> for u8 {
    #[inline(always)]
    fn from(variant: Actphyif) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Actphyif {
    type Ux = u8;
}
#[doc = "Field `actphyif` reader - When you have multiple PHY interfaces in your configuration, this field indicates the sampled value of emacx_phy_if_selduring reset de-assertion."]
pub type ActphyifR = crate::FieldReader<Actphyif>;
impl ActphyifR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Actphyif {
        match self.bits {
            0 => Actphyif::Gmiimii0,
            1 => Actphyif::Rgmii1,
            2 => Actphyif::Sgmii2,
            3 => Actphyif::Tbi3,
            4 => Actphyif::Rmii4,
            5 => Actphyif::Rtbi5,
            6 => Actphyif::Smii6,
            7 => Actphyif::Revmii7,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gmiimii0(&self) -> bool {
        *self == Actphyif::Gmiimii0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rgmii1(&self) -> bool {
        *self == Actphyif::Rgmii1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_sgmii2(&self) -> bool {
        *self == Actphyif::Sgmii2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_tbi3(&self) -> bool {
        *self == Actphyif::Tbi3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_rmii4(&self) -> bool {
        *self == Actphyif::Rmii4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_rtbi5(&self) -> bool {
        *self == Actphyif::Rtbi5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_smii6(&self) -> bool {
        *self == Actphyif::Smii6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_revmii7(&self) -> bool {
        *self == Actphyif::Revmii7
    }
}
#[doc = "Field `actphyif` writer - When you have multiple PHY interfaces in your configuration, this field indicates the sampled value of emacx_phy_if_selduring reset de-assertion."]
pub type ActphyifW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bit 0 - 10/100 Mbps support"]
    #[inline(always)]
    pub fn miisel(&self) -> MiiselR {
        MiiselR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - 1000 Mbps support"]
    #[inline(always)]
    pub fn gmiisel(&self) -> GmiiselR {
        GmiiselR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Half-Duplex support"]
    #[inline(always)]
    pub fn hdsel(&self) -> HdselR {
        HdselR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - HASH Filter support"]
    #[inline(always)]
    pub fn hashsel(&self) -> HashselR {
        HashselR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Multiple MAC Address Registers support"]
    #[inline(always)]
    pub fn addmacadrsel(&self) -> AddmacadrselR {
        AddmacadrselR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - TBI/SGMII/RTBI PHY interface support"]
    #[inline(always)]
    pub fn pcssel(&self) -> PcsselR {
        PcsselR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - SMA (MDIO) Interface support"]
    #[inline(always)]
    pub fn smasel(&self) -> SmaselR {
        SmaselR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - PMT Remote Wakeup support"]
    #[inline(always)]
    pub fn rwksel(&self) -> RwkselR {
        RwkselR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - PMT Magic Packet"]
    #[inline(always)]
    pub fn mgksel(&self) -> MgkselR {
        MgkselR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - RMON block"]
    #[inline(always)]
    pub fn mmcsel(&self) -> MmcselR {
        MmcselR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Only IEEE 1588-2002 Timestamp"]
    #[inline(always)]
    pub fn tsver1sel(&self) -> Tsver1selR {
        Tsver1selR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - IEEE 1588-2008 Advanced Timestamp"]
    #[inline(always)]
    pub fn tsver2sel(&self) -> Tsver2selR {
        Tsver2selR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Energy Efficient Ethernet Feature"]
    #[inline(always)]
    pub fn eeesel(&self) -> EeeselR {
        EeeselR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - AV Feature"]
    #[inline(always)]
    pub fn avsel(&self) -> AvselR {
        AvselR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Checksum Offload in Tx"]
    #[inline(always)]
    pub fn txoesel(&self) -> TxoeselR {
        TxoeselR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - IP Checksum Offload (Type 1) in Rx"]
    #[inline(always)]
    pub fn rxtyp1coe(&self) -> Rxtyp1coeR {
        Rxtyp1coeR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - IP Checksum Offload (Type 2) in Rx"]
    #[inline(always)]
    pub fn rxtyp2coe(&self) -> Rxtyp2coeR {
        Rxtyp2coeR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - RxFIFO > 2048 Bytes"]
    #[inline(always)]
    pub fn rxfifosize(&self) -> RxfifosizeR {
        RxfifosizeR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bits 20:21 - Number of additional Rx channels"]
    #[inline(always)]
    pub fn rxchcnt(&self) -> RxchcntR {
        RxchcntR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bits 22:23 - Number of additional Tx channels"]
    #[inline(always)]
    pub fn txchcnt(&self) -> TxchcntR {
        TxchcntR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bit 24 - Alternate (Enhanced Descriptor)"]
    #[inline(always)]
    pub fn enhdessel(&self) -> EnhdesselR {
        EnhdesselR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bits 28:30 - When you have multiple PHY interfaces in your configuration, this field indicates the sampled value of emacx_phy_if_selduring reset de-assertion."]
    #[inline(always)]
    pub fn actphyif(&self) -> ActphyifR {
        ActphyifR::new(((self.bits >> 28) & 7) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - 10/100 Mbps support"]
    #[inline(always)]
    #[must_use]
    pub fn miisel(&mut self) -> MiiselW<DmagrpHwFeatureSpec> {
        MiiselW::new(self, 0)
    }
    #[doc = "Bit 1 - 1000 Mbps support"]
    #[inline(always)]
    #[must_use]
    pub fn gmiisel(&mut self) -> GmiiselW<DmagrpHwFeatureSpec> {
        GmiiselW::new(self, 1)
    }
    #[doc = "Bit 2 - Half-Duplex support"]
    #[inline(always)]
    #[must_use]
    pub fn hdsel(&mut self) -> HdselW<DmagrpHwFeatureSpec> {
        HdselW::new(self, 2)
    }
    #[doc = "Bit 4 - HASH Filter support"]
    #[inline(always)]
    #[must_use]
    pub fn hashsel(&mut self) -> HashselW<DmagrpHwFeatureSpec> {
        HashselW::new(self, 4)
    }
    #[doc = "Bit 5 - Multiple MAC Address Registers support"]
    #[inline(always)]
    #[must_use]
    pub fn addmacadrsel(&mut self) -> AddmacadrselW<DmagrpHwFeatureSpec> {
        AddmacadrselW::new(self, 5)
    }
    #[doc = "Bit 6 - TBI/SGMII/RTBI PHY interface support"]
    #[inline(always)]
    #[must_use]
    pub fn pcssel(&mut self) -> PcsselW<DmagrpHwFeatureSpec> {
        PcsselW::new(self, 6)
    }
    #[doc = "Bit 8 - SMA (MDIO) Interface support"]
    #[inline(always)]
    #[must_use]
    pub fn smasel(&mut self) -> SmaselW<DmagrpHwFeatureSpec> {
        SmaselW::new(self, 8)
    }
    #[doc = "Bit 9 - PMT Remote Wakeup support"]
    #[inline(always)]
    #[must_use]
    pub fn rwksel(&mut self) -> RwkselW<DmagrpHwFeatureSpec> {
        RwkselW::new(self, 9)
    }
    #[doc = "Bit 10 - PMT Magic Packet"]
    #[inline(always)]
    #[must_use]
    pub fn mgksel(&mut self) -> MgkselW<DmagrpHwFeatureSpec> {
        MgkselW::new(self, 10)
    }
    #[doc = "Bit 11 - RMON block"]
    #[inline(always)]
    #[must_use]
    pub fn mmcsel(&mut self) -> MmcselW<DmagrpHwFeatureSpec> {
        MmcselW::new(self, 11)
    }
    #[doc = "Bit 12 - Only IEEE 1588-2002 Timestamp"]
    #[inline(always)]
    #[must_use]
    pub fn tsver1sel(&mut self) -> Tsver1selW<DmagrpHwFeatureSpec> {
        Tsver1selW::new(self, 12)
    }
    #[doc = "Bit 13 - IEEE 1588-2008 Advanced Timestamp"]
    #[inline(always)]
    #[must_use]
    pub fn tsver2sel(&mut self) -> Tsver2selW<DmagrpHwFeatureSpec> {
        Tsver2selW::new(self, 13)
    }
    #[doc = "Bit 14 - Energy Efficient Ethernet Feature"]
    #[inline(always)]
    #[must_use]
    pub fn eeesel(&mut self) -> EeeselW<DmagrpHwFeatureSpec> {
        EeeselW::new(self, 14)
    }
    #[doc = "Bit 15 - AV Feature"]
    #[inline(always)]
    #[must_use]
    pub fn avsel(&mut self) -> AvselW<DmagrpHwFeatureSpec> {
        AvselW::new(self, 15)
    }
    #[doc = "Bit 16 - Checksum Offload in Tx"]
    #[inline(always)]
    #[must_use]
    pub fn txoesel(&mut self) -> TxoeselW<DmagrpHwFeatureSpec> {
        TxoeselW::new(self, 16)
    }
    #[doc = "Bit 17 - IP Checksum Offload (Type 1) in Rx"]
    #[inline(always)]
    #[must_use]
    pub fn rxtyp1coe(&mut self) -> Rxtyp1coeW<DmagrpHwFeatureSpec> {
        Rxtyp1coeW::new(self, 17)
    }
    #[doc = "Bit 18 - IP Checksum Offload (Type 2) in Rx"]
    #[inline(always)]
    #[must_use]
    pub fn rxtyp2coe(&mut self) -> Rxtyp2coeW<DmagrpHwFeatureSpec> {
        Rxtyp2coeW::new(self, 18)
    }
    #[doc = "Bit 19 - RxFIFO > 2048 Bytes"]
    #[inline(always)]
    #[must_use]
    pub fn rxfifosize(&mut self) -> RxfifosizeW<DmagrpHwFeatureSpec> {
        RxfifosizeW::new(self, 19)
    }
    #[doc = "Bits 20:21 - Number of additional Rx channels"]
    #[inline(always)]
    #[must_use]
    pub fn rxchcnt(&mut self) -> RxchcntW<DmagrpHwFeatureSpec> {
        RxchcntW::new(self, 20)
    }
    #[doc = "Bits 22:23 - Number of additional Tx channels"]
    #[inline(always)]
    #[must_use]
    pub fn txchcnt(&mut self) -> TxchcntW<DmagrpHwFeatureSpec> {
        TxchcntW::new(self, 22)
    }
    #[doc = "Bit 24 - Alternate (Enhanced Descriptor)"]
    #[inline(always)]
    #[must_use]
    pub fn enhdessel(&mut self) -> EnhdesselW<DmagrpHwFeatureSpec> {
        EnhdesselW::new(self, 24)
    }
    #[doc = "Bits 28:30 - When you have multiple PHY interfaces in your configuration, this field indicates the sampled value of emacx_phy_if_selduring reset de-assertion."]
    #[inline(always)]
    #[must_use]
    pub fn actphyif(&mut self) -> ActphyifW<DmagrpHwFeatureSpec> {
        ActphyifW::new(self, 28)
    }
}
#[doc = "This register indicates the presence of the optional features or functions of the gmac. The software driver can use this register to dynamically enable or disable the programs related to the optional blocks.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_hw_feature::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpHwFeatureSpec;
impl crate::RegisterSpec for DmagrpHwFeatureSpec {
    type Ux = u32;
    const OFFSET: u64 = 4184u64;
}
#[doc = "`read()` method returns [`dmagrp_hw_feature::R`](R) reader structure"]
impl crate::Readable for DmagrpHwFeatureSpec {}
#[doc = "`reset()` method sets dmagrp_HW_Feature to value 0x010d_7f37"]
impl crate::Resettable for DmagrpHwFeatureSpec {
    const RESET_VALUE: u32 = 0x010d_7f37;
}
