// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_ghwcfg4` reader"]
pub type R = crate::R<GlobgrpGhwcfg4Spec>;
#[doc = "Register `globgrp_ghwcfg4` writer"]
pub type W = crate::W<GlobgrpGhwcfg4Spec>;
#[doc = "Field `numdevperioeps` reader - The maximum number of device IN operations is 16 active at any time including endpoint 0, which is always present. This parameter determines the number of device mode Tx FIFOs to be instantiated."]
pub type NumdevperioepsR = crate::FieldReader;
#[doc = "Field `numdevperioeps` writer - The maximum number of device IN operations is 16 active at any time including endpoint 0, which is always present. This parameter determines the number of device mode Tx FIFOs to be instantiated."]
pub type NumdevperioepsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Specifies whether to enable power optimization.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Partialpwrdn {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Partialpwrdn> for bool {
    #[inline(always)]
    fn from(variant: Partialpwrdn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `partialpwrdn` reader - Specifies whether to enable power optimization."]
pub type PartialpwrdnR = crate::BitReader<Partialpwrdn>;
impl PartialpwrdnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Partialpwrdn> {
        match self.bits {
            false => Some(Partialpwrdn::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Partialpwrdn::Disabled
    }
}
#[doc = "Field `partialpwrdn` writer - Specifies whether to enable power optimization."]
pub type PartialpwrdnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When the AHB frequency is less than 60 MHz, 4-deep clock-domain crossing sink and source buffers are instantiated between the MAC and the Packet FIFO Controller (PFC); otherwise, two-deep buffers are sufficient.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ahbfreq {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ahbfreq> for bool {
    #[inline(always)]
    fn from(variant: Ahbfreq) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ahbfreq` reader - When the AHB frequency is less than 60 MHz, 4-deep clock-domain crossing sink and source buffers are instantiated between the MAC and the Packet FIFO Controller (PFC); otherwise, two-deep buffers are sufficient."]
pub type AhbfreqR = crate::BitReader<Ahbfreq>;
impl AhbfreqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ahbfreq> {
        match self.bits {
            true => Some(Ahbfreq::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ahbfreq::Enabled
    }
}
#[doc = "Field `ahbfreq` writer - When the AHB frequency is less than 60 MHz, 4-deep clock-domain crossing sink and source buffers are instantiated between the MAC and the Packet FIFO Controller (PFC); otherwise, two-deep buffers are sufficient."]
pub type AhbfreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Enables power saving mode hibernation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hibernation {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Hibernation> for bool {
    #[inline(always)]
    fn from(variant: Hibernation) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hibernation` reader - Enables power saving mode hibernation."]
pub type HibernationR = crate::BitReader<Hibernation>;
impl HibernationR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Hibernation> {
        match self.bits {
            false => Some(Hibernation::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hibernation::Disabled
    }
}
#[doc = "Field `hibernation` writer - Enables power saving mode hibernation."]
pub type HibernationW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `phydatawidth` reader - Uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
pub type PhydatawidthR = crate::FieldReader;
#[doc = "Field `phydatawidth` writer - Uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
pub type PhydatawidthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Specifies the number of Device mode control endpoints in addition to control endpoint 0, which is always present. Range: 0-15.\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Numctleps {
    #[doc = "0: `0`"]
    Endpt0 = 0,
    #[doc = "1: `1`"]
    Endpt1 = 1,
    #[doc = "2: `10`"]
    Endpt2 = 2,
    #[doc = "3: `11`"]
    Endpt3 = 3,
    #[doc = "4: `100`"]
    Endpt4 = 4,
    #[doc = "5: `101`"]
    Endpt5 = 5,
    #[doc = "6: `110`"]
    Endpt6 = 6,
    #[doc = "7: `111`"]
    Endpt7 = 7,
    #[doc = "8: `1000`"]
    Endpt8 = 8,
    #[doc = "9: `1001`"]
    Endpt9 = 9,
    #[doc = "10: `1010`"]
    Endpt10 = 10,
    #[doc = "11: `1011`"]
    Endpt11 = 11,
    #[doc = "12: `1100`"]
    Endpt12 = 12,
    #[doc = "13: `1101`"]
    Endpt13 = 13,
    #[doc = "14: `1110`"]
    Endpt14 = 14,
    #[doc = "15: `1111`"]
    Endpt15 = 15,
}
impl From<Numctleps> for u8 {
    #[inline(always)]
    fn from(variant: Numctleps) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Numctleps {
    type Ux = u8;
}
#[doc = "Field `numctleps` reader - Specifies the number of Device mode control endpoints in addition to control endpoint 0, which is always present. Range: 0-15."]
pub type NumctlepsR = crate::FieldReader<Numctleps>;
impl NumctlepsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Numctleps {
        match self.bits {
            0 => Numctleps::Endpt0,
            1 => Numctleps::Endpt1,
            2 => Numctleps::Endpt2,
            3 => Numctleps::Endpt3,
            4 => Numctleps::Endpt4,
            5 => Numctleps::Endpt5,
            6 => Numctleps::Endpt6,
            7 => Numctleps::Endpt7,
            8 => Numctleps::Endpt8,
            9 => Numctleps::Endpt9,
            10 => Numctleps::Endpt10,
            11 => Numctleps::Endpt11,
            12 => Numctleps::Endpt12,
            13 => Numctleps::Endpt13,
            14 => Numctleps::Endpt14,
            15 => Numctleps::Endpt15,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_endpt0(&self) -> bool {
        *self == Numctleps::Endpt0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_endpt1(&self) -> bool {
        *self == Numctleps::Endpt1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_endpt2(&self) -> bool {
        *self == Numctleps::Endpt2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_endpt3(&self) -> bool {
        *self == Numctleps::Endpt3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_endpt4(&self) -> bool {
        *self == Numctleps::Endpt4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_endpt5(&self) -> bool {
        *self == Numctleps::Endpt5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_endpt6(&self) -> bool {
        *self == Numctleps::Endpt6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_endpt7(&self) -> bool {
        *self == Numctleps::Endpt7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_endpt8(&self) -> bool {
        *self == Numctleps::Endpt8
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_endpt9(&self) -> bool {
        *self == Numctleps::Endpt9
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_endpt10(&self) -> bool {
        *self == Numctleps::Endpt10
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_endpt11(&self) -> bool {
        *self == Numctleps::Endpt11
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_endpt12(&self) -> bool {
        *self == Numctleps::Endpt12
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_endpt13(&self) -> bool {
        *self == Numctleps::Endpt13
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_endpt14(&self) -> bool {
        *self == Numctleps::Endpt14
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_endpt15(&self) -> bool {
        *self == Numctleps::Endpt15
    }
}
#[doc = "Field `numctleps` writer - Specifies the number of Device mode control endpoints in addition to control endpoint 0, which is always present. Range: 0-15."]
pub type NumctlepsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Specifies whether to add a filter on the iddig input from the PHY. This is not relevant since we only support ULPI and there is no iddig pin exposed to I/O pads.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Iddgfltr {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Iddgfltr> for bool {
    #[inline(always)]
    fn from(variant: Iddgfltr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `iddgfltr` reader - Specifies whether to add a filter on the iddig input from the PHY. This is not relevant since we only support ULPI and there is no iddig pin exposed to I/O pads."]
pub type IddgfltrR = crate::BitReader<Iddgfltr>;
impl IddgfltrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Iddgfltr> {
        match self.bits {
            false => Some(Iddgfltr::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Iddgfltr::Disabled
    }
}
#[doc = "Field `iddgfltr` writer - Specifies whether to add a filter on the iddig input from the PHY. This is not relevant since we only support ULPI and there is no iddig pin exposed to I/O pads."]
pub type IddgfltrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Vbus Valid Filter Enabled (VBusValidFltr) 0: No filter 1: Filter(coreConsultant parameter: OTG_EN_VBUSVALID_FILTER)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vbusvalidfltr {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Vbusvalidfltr> for bool {
    #[inline(always)]
    fn from(variant: Vbusvalidfltr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vbusvalidfltr` reader - Vbus Valid Filter Enabled (VBusValidFltr) 0: No filter 1: Filter(coreConsultant parameter: OTG_EN_VBUSVALID_FILTER)"]
pub type VbusvalidfltrR = crate::BitReader<Vbusvalidfltr>;
impl VbusvalidfltrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Vbusvalidfltr> {
        match self.bits {
            false => Some(Vbusvalidfltr::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Vbusvalidfltr::Disabled
    }
}
#[doc = "Field `vbusvalidfltr` writer - Vbus Valid Filter Enabled (VBusValidFltr) 0: No filter 1: Filter(coreConsultant parameter: OTG_EN_VBUSVALID_FILTER)"]
pub type VbusvalidfltrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies whether to add a filter on the b_valid input from the PHY.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Avalidfltr {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Avalidfltr> for bool {
    #[inline(always)]
    fn from(variant: Avalidfltr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `avalidfltr` reader - Specifies whether to add a filter on the b_valid input from the PHY."]
pub type AvalidfltrR = crate::BitReader<Avalidfltr>;
impl AvalidfltrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Avalidfltr> {
        match self.bits {
            false => Some(Avalidfltr::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Avalidfltr::Disabled
    }
}
#[doc = "Field `avalidfltr` writer - Specifies whether to add a filter on the b_valid input from the PHY."]
pub type AvalidfltrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies whether to add a filter on the b_valid input from the PHY.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bvalidfltr {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Bvalidfltr> for bool {
    #[inline(always)]
    fn from(variant: Bvalidfltr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bvalidfltr` reader - Specifies whether to add a filter on the b_valid input from the PHY."]
pub type BvalidfltrR = crate::BitReader<Bvalidfltr>;
impl BvalidfltrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Bvalidfltr> {
        match self.bits {
            false => Some(Bvalidfltr::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Bvalidfltr::Disabled
    }
}
#[doc = "Field `bvalidfltr` writer - Specifies whether to add a filter on the b_valid input from the PHY."]
pub type BvalidfltrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies whether to add a filter on the session_end input from the PHY.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sessendfltr {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Sessendfltr> for bool {
    #[inline(always)]
    fn from(variant: Sessendfltr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sessendfltr` reader - Specifies whether to add a filter on the session_end input from the PHY."]
pub type SessendfltrR = crate::BitReader<Sessendfltr>;
impl SessendfltrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Sessendfltr> {
        match self.bits {
            false => Some(Sessendfltr::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Sessendfltr::Disabled
    }
}
#[doc = "Field `sessendfltr` writer - Specifies whether to add a filter on the session_end input from the PHY."]
pub type SessendfltrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies whether Dedicated Transmit FIFOs should be enabled in device mode.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dedfifomode {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dedfifomode> for bool {
    #[inline(always)]
    fn from(variant: Dedfifomode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dedfifomode` reader - Specifies whether Dedicated Transmit FIFOs should be enabled in device mode."]
pub type DedfifomodeR = crate::BitReader<Dedfifomode>;
impl DedfifomodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dedfifomode> {
        match self.bits {
            true => Some(Dedfifomode::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dedfifomode::Enabled
    }
}
#[doc = "Field `dedfifomode` writer - Specifies whether Dedicated Transmit FIFOs should be enabled in device mode."]
pub type DedfifomodeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Number of Device Mode IN Endpoints Including Control.\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ineps {
    #[doc = "0: `0`"]
    Endpt1 = 0,
    #[doc = "1: `1`"]
    Endpt2 = 1,
    #[doc = "2: `10`"]
    Endpt3 = 2,
    #[doc = "3: `11`"]
    Endpt4 = 3,
    #[doc = "4: `100`"]
    Endpt5 = 4,
    #[doc = "5: `101`"]
    Endpt6 = 5,
    #[doc = "6: `110`"]
    Endpt7 = 6,
    #[doc = "7: `111`"]
    Endpt8 = 7,
    #[doc = "8: `1000`"]
    Endpt9 = 8,
    #[doc = "9: `1001`"]
    Endpt10 = 9,
    #[doc = "10: `1010`"]
    Endpt11 = 10,
    #[doc = "11: `1011`"]
    Endpt12 = 11,
    #[doc = "12: `1100`"]
    Endpt13 = 12,
    #[doc = "13: `1101`"]
    Endpt14 = 13,
    #[doc = "14: `1110`"]
    Endpt15 = 14,
    #[doc = "15: `1111`"]
    Endpt16 = 15,
}
impl From<Ineps> for u8 {
    #[inline(always)]
    fn from(variant: Ineps) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ineps {
    type Ux = u8;
}
#[doc = "Field `ineps` reader - Number of Device Mode IN Endpoints Including Control."]
pub type InepsR = crate::FieldReader<Ineps>;
impl InepsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ineps {
        match self.bits {
            0 => Ineps::Endpt1,
            1 => Ineps::Endpt2,
            2 => Ineps::Endpt3,
            3 => Ineps::Endpt4,
            4 => Ineps::Endpt5,
            5 => Ineps::Endpt6,
            6 => Ineps::Endpt7,
            7 => Ineps::Endpt8,
            8 => Ineps::Endpt9,
            9 => Ineps::Endpt10,
            10 => Ineps::Endpt11,
            11 => Ineps::Endpt12,
            12 => Ineps::Endpt13,
            13 => Ineps::Endpt14,
            14 => Ineps::Endpt15,
            15 => Ineps::Endpt16,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_endpt1(&self) -> bool {
        *self == Ineps::Endpt1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_endpt2(&self) -> bool {
        *self == Ineps::Endpt2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_endpt3(&self) -> bool {
        *self == Ineps::Endpt3
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_endpt4(&self) -> bool {
        *self == Ineps::Endpt4
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_endpt5(&self) -> bool {
        *self == Ineps::Endpt5
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_endpt6(&self) -> bool {
        *self == Ineps::Endpt6
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_endpt7(&self) -> bool {
        *self == Ineps::Endpt7
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_endpt8(&self) -> bool {
        *self == Ineps::Endpt8
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_endpt9(&self) -> bool {
        *self == Ineps::Endpt9
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_endpt10(&self) -> bool {
        *self == Ineps::Endpt10
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_endpt11(&self) -> bool {
        *self == Ineps::Endpt11
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_endpt12(&self) -> bool {
        *self == Ineps::Endpt12
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_endpt13(&self) -> bool {
        *self == Ineps::Endpt13
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_endpt14(&self) -> bool {
        *self == Ineps::Endpt14
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_endpt15(&self) -> bool {
        *self == Ineps::Endpt15
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_endpt16(&self) -> bool {
        *self == Ineps::Endpt16
    }
}
#[doc = "Field `ineps` writer - Number of Device Mode IN Endpoints Including Control."]
pub type InepsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Selects bewteen scatter and nonscatter configuration\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaConfiguration {
    #[doc = "0: `0`"]
    Nonscatter = 0,
    #[doc = "1: `1`"]
    Scatter = 1,
}
impl From<DmaConfiguration> for bool {
    #[inline(always)]
    fn from(variant: DmaConfiguration) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dma_configuration` reader - Selects bewteen scatter and nonscatter configuration"]
pub type DmaConfigurationR = crate::BitReader<DmaConfiguration>;
impl DmaConfigurationR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DmaConfiguration {
        match self.bits {
            false => DmaConfiguration::Nonscatter,
            true => DmaConfiguration::Scatter,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nonscatter(&self) -> bool {
        *self == DmaConfiguration::Nonscatter
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_scatter(&self) -> bool {
        *self == DmaConfiguration::Scatter
    }
}
#[doc = "Field `dma_configuration` writer - Selects bewteen scatter and nonscatter configuration"]
pub type DmaConfigurationW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Enable descriptor based scatter/gather DMA. When enabled, DMA operations will be serviced with descriptor based scatter/gather DMA\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dma {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dma> for bool {
    #[inline(always)]
    fn from(variant: Dma) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dma` reader - Enable descriptor based scatter/gather DMA. When enabled, DMA operations will be serviced with descriptor based scatter/gather DMA"]
pub type DmaR = crate::BitReader<Dma>;
impl DmaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dma> {
        match self.bits {
            true => Some(Dma::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dma::Enabled
    }
}
#[doc = "Field `dma` writer - Enable descriptor based scatter/gather DMA. When enabled, DMA operations will be serviced with descriptor based scatter/gather DMA"]
pub type DmaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:3 - The maximum number of device IN operations is 16 active at any time including endpoint 0, which is always present. This parameter determines the number of device mode Tx FIFOs to be instantiated."]
    #[inline(always)]
    pub fn numdevperioeps(&self) -> NumdevperioepsR {
        NumdevperioepsR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 4 - Specifies whether to enable power optimization."]
    #[inline(always)]
    pub fn partialpwrdn(&self) -> PartialpwrdnR {
        PartialpwrdnR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When the AHB frequency is less than 60 MHz, 4-deep clock-domain crossing sink and source buffers are instantiated between the MAC and the Packet FIFO Controller (PFC); otherwise, two-deep buffers are sufficient."]
    #[inline(always)]
    pub fn ahbfreq(&self) -> AhbfreqR {
        AhbfreqR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Enables power saving mode hibernation."]
    #[inline(always)]
    pub fn hibernation(&self) -> HibernationR {
        HibernationR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 14:15 - Uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
    #[inline(always)]
    pub fn phydatawidth(&self) -> PhydatawidthR {
        PhydatawidthR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bits 16:19 - Specifies the number of Device mode control endpoints in addition to control endpoint 0, which is always present. Range: 0-15."]
    #[inline(always)]
    pub fn numctleps(&self) -> NumctlepsR {
        NumctlepsR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bit 20 - Specifies whether to add a filter on the iddig input from the PHY. This is not relevant since we only support ULPI and there is no iddig pin exposed to I/O pads."]
    #[inline(always)]
    pub fn iddgfltr(&self) -> IddgfltrR {
        IddgfltrR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Vbus Valid Filter Enabled (VBusValidFltr) 0: No filter 1: Filter(coreConsultant parameter: OTG_EN_VBUSVALID_FILTER)"]
    #[inline(always)]
    pub fn vbusvalidfltr(&self) -> VbusvalidfltrR {
        VbusvalidfltrR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Specifies whether to add a filter on the b_valid input from the PHY."]
    #[inline(always)]
    pub fn avalidfltr(&self) -> AvalidfltrR {
        AvalidfltrR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Specifies whether to add a filter on the b_valid input from the PHY."]
    #[inline(always)]
    pub fn bvalidfltr(&self) -> BvalidfltrR {
        BvalidfltrR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Specifies whether to add a filter on the session_end input from the PHY."]
    #[inline(always)]
    pub fn sessendfltr(&self) -> SessendfltrR {
        SessendfltrR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Specifies whether Dedicated Transmit FIFOs should be enabled in device mode."]
    #[inline(always)]
    pub fn dedfifomode(&self) -> DedfifomodeR {
        DedfifomodeR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bits 26:29 - Number of Device Mode IN Endpoints Including Control."]
    #[inline(always)]
    pub fn ineps(&self) -> InepsR {
        InepsR::new(((self.bits >> 26) & 0x0f) as u8)
    }
    #[doc = "Bit 30 - Selects bewteen scatter and nonscatter configuration"]
    #[inline(always)]
    pub fn dma_configuration(&self) -> DmaConfigurationR {
        DmaConfigurationR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Enable descriptor based scatter/gather DMA. When enabled, DMA operations will be serviced with descriptor based scatter/gather DMA"]
    #[inline(always)]
    pub fn dma(&self) -> DmaR {
        DmaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:3 - The maximum number of device IN operations is 16 active at any time including endpoint 0, which is always present. This parameter determines the number of device mode Tx FIFOs to be instantiated."]
    #[inline(always)]
    #[must_use]
    pub fn numdevperioeps(&mut self) -> NumdevperioepsW<GlobgrpGhwcfg4Spec> {
        NumdevperioepsW::new(self, 0)
    }
    #[doc = "Bit 4 - Specifies whether to enable power optimization."]
    #[inline(always)]
    #[must_use]
    pub fn partialpwrdn(&mut self) -> PartialpwrdnW<GlobgrpGhwcfg4Spec> {
        PartialpwrdnW::new(self, 4)
    }
    #[doc = "Bit 5 - When the AHB frequency is less than 60 MHz, 4-deep clock-domain crossing sink and source buffers are instantiated between the MAC and the Packet FIFO Controller (PFC); otherwise, two-deep buffers are sufficient."]
    #[inline(always)]
    #[must_use]
    pub fn ahbfreq(&mut self) -> AhbfreqW<GlobgrpGhwcfg4Spec> {
        AhbfreqW::new(self, 5)
    }
    #[doc = "Bit 6 - Enables power saving mode hibernation."]
    #[inline(always)]
    #[must_use]
    pub fn hibernation(&mut self) -> HibernationW<GlobgrpGhwcfg4Spec> {
        HibernationW::new(self, 6)
    }
    #[doc = "Bits 14:15 - Uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
    #[inline(always)]
    #[must_use]
    pub fn phydatawidth(&mut self) -> PhydatawidthW<GlobgrpGhwcfg4Spec> {
        PhydatawidthW::new(self, 14)
    }
    #[doc = "Bits 16:19 - Specifies the number of Device mode control endpoints in addition to control endpoint 0, which is always present. Range: 0-15."]
    #[inline(always)]
    #[must_use]
    pub fn numctleps(&mut self) -> NumctlepsW<GlobgrpGhwcfg4Spec> {
        NumctlepsW::new(self, 16)
    }
    #[doc = "Bit 20 - Specifies whether to add a filter on the iddig input from the PHY. This is not relevant since we only support ULPI and there is no iddig pin exposed to I/O pads."]
    #[inline(always)]
    #[must_use]
    pub fn iddgfltr(&mut self) -> IddgfltrW<GlobgrpGhwcfg4Spec> {
        IddgfltrW::new(self, 20)
    }
    #[doc = "Bit 21 - Vbus Valid Filter Enabled (VBusValidFltr) 0: No filter 1: Filter(coreConsultant parameter: OTG_EN_VBUSVALID_FILTER)"]
    #[inline(always)]
    #[must_use]
    pub fn vbusvalidfltr(&mut self) -> VbusvalidfltrW<GlobgrpGhwcfg4Spec> {
        VbusvalidfltrW::new(self, 21)
    }
    #[doc = "Bit 22 - Specifies whether to add a filter on the b_valid input from the PHY."]
    #[inline(always)]
    #[must_use]
    pub fn avalidfltr(&mut self) -> AvalidfltrW<GlobgrpGhwcfg4Spec> {
        AvalidfltrW::new(self, 22)
    }
    #[doc = "Bit 23 - Specifies whether to add a filter on the b_valid input from the PHY."]
    #[inline(always)]
    #[must_use]
    pub fn bvalidfltr(&mut self) -> BvalidfltrW<GlobgrpGhwcfg4Spec> {
        BvalidfltrW::new(self, 23)
    }
    #[doc = "Bit 24 - Specifies whether to add a filter on the session_end input from the PHY."]
    #[inline(always)]
    #[must_use]
    pub fn sessendfltr(&mut self) -> SessendfltrW<GlobgrpGhwcfg4Spec> {
        SessendfltrW::new(self, 24)
    }
    #[doc = "Bit 25 - Specifies whether Dedicated Transmit FIFOs should be enabled in device mode."]
    #[inline(always)]
    #[must_use]
    pub fn dedfifomode(&mut self) -> DedfifomodeW<GlobgrpGhwcfg4Spec> {
        DedfifomodeW::new(self, 25)
    }
    #[doc = "Bits 26:29 - Number of Device Mode IN Endpoints Including Control."]
    #[inline(always)]
    #[must_use]
    pub fn ineps(&mut self) -> InepsW<GlobgrpGhwcfg4Spec> {
        InepsW::new(self, 26)
    }
    #[doc = "Bit 30 - Selects bewteen scatter and nonscatter configuration"]
    #[inline(always)]
    #[must_use]
    pub fn dma_configuration(&mut self) -> DmaConfigurationW<GlobgrpGhwcfg4Spec> {
        DmaConfigurationW::new(self, 30)
    }
    #[doc = "Bit 31 - Enable descriptor based scatter/gather DMA. When enabled, DMA operations will be serviced with descriptor based scatter/gather DMA"]
    #[inline(always)]
    #[must_use]
    pub fn dma(&mut self) -> DmaW<GlobgrpGhwcfg4Spec> {
        DmaW::new(self, 31)
    }
}
#[doc = "This register contains the configuration options.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGhwcfg4Spec;
impl crate::RegisterSpec for GlobgrpGhwcfg4Spec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`globgrp_ghwcfg4::R`](R) reader structure"]
impl crate::Readable for GlobgrpGhwcfg4Spec {}
#[doc = "`reset()` method sets globgrp_ghwcfg4 to value 0xfe0f_0020"]
impl crate::Resettable for GlobgrpGhwcfg4Spec {
    const RESET_VALUE: u32 = 0xfe0f_0020;
}
