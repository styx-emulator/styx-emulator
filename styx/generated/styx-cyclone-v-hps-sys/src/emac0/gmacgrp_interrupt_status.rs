// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Interrupt_Status` reader"]
pub type R = crate::R<GmacgrpInterruptStatusSpec>;
#[doc = "Register `gmacgrp_Interrupt_Status` writer"]
pub type W = crate::W<GmacgrpInterruptStatusSpec>;
#[doc = "This bit is set because of any change in value of the Link Status of RGMII or SMII interface (Bit 3 in Register 54 (SGMII/RGMII/SMII Status Register)). This bit is cleared when you perform a read operation on the SGMII/RGMII/SMII Status Register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rgsmiiis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rgsmiiis> for bool {
    #[inline(always)]
    fn from(variant: Rgsmiiis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rgsmiiis` reader - This bit is set because of any change in value of the Link Status of RGMII or SMII interface (Bit 3 in Register 54 (SGMII/RGMII/SMII Status Register)). This bit is cleared when you perform a read operation on the SGMII/RGMII/SMII Status Register."]
pub type RgsmiiisR = crate::BitReader<Rgsmiiis>;
impl RgsmiiisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rgsmiiis {
        match self.bits {
            false => Rgsmiiis::Inactive,
            true => Rgsmiiis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rgsmiiis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rgsmiiis::Active
    }
}
#[doc = "Field `rgsmiiis` writer - This bit is set because of any change in value of the Link Status of RGMII or SMII interface (Bit 3 in Register 54 (SGMII/RGMII/SMII Status Register)). This bit is cleared when you perform a read operation on the SGMII/RGMII/SMII Status Register."]
pub type RgsmiiisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `pcslchgis` reader - This bit is set because of any change in Link Status in the TBI, RTBI, or SGMII PHY interface (Bit 2 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation on the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
pub type PcslchgisR = crate::BitReader;
#[doc = "Field `pcslchgis` writer - This bit is set because of any change in Link Status in the TBI, RTBI, or SGMII PHY interface (Bit 2 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation on the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
pub type PcslchgisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `pcsancis` reader - This bit is set when the Auto-negotiation is completed in the TBI, RTBI, or SGMII PHY interface (Bit 5 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation to the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
pub type PcsancisR = crate::BitReader;
#[doc = "Field `pcsancis` writer - This bit is set when the Auto-negotiation is completed in the TBI, RTBI, or SGMII PHY interface (Bit 5 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation to the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
pub type PcsancisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set high when any of the Bits \\[7:5\\]
is set high and cleared only when all of these bits are low.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mmcis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Mmcis> for bool {
    #[inline(always)]
    fn from(variant: Mmcis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mmcis` reader - This bit is set high when any of the Bits \\[7:5\\]
is set high and cleared only when all of these bits are low."]
pub type MmcisR = crate::BitReader<Mmcis>;
impl MmcisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mmcis {
        match self.bits {
            false => Mmcis::Inactive,
            true => Mmcis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Mmcis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Mmcis::Active
    }
}
#[doc = "Field `mmcis` writer - This bit is set high when any of the Bits \\[7:5\\]
is set high and cleared only when all of these bits are low."]
pub type MmcisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set high when an interrupt is generated in the MMC Receive Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mmcrxis {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Mmcrxis> for bool {
    #[inline(always)]
    fn from(variant: Mmcrxis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mmcrxis` reader - This bit is set high when an interrupt is generated in the MMC Receive Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
pub type MmcrxisR = crate::BitReader<Mmcrxis>;
impl MmcrxisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mmcrxis {
        match self.bits {
            false => Mmcrxis::Disabled,
            true => Mmcrxis::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Mmcrxis::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Mmcrxis::Enabled
    }
}
#[doc = "Field `mmcrxis` writer - This bit is set high when an interrupt is generated in the MMC Receive Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
pub type MmcrxisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set high when an interrupt is generated in the MMC Transmit Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mmctxis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Mmctxis> for bool {
    #[inline(always)]
    fn from(variant: Mmctxis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mmctxis` reader - This bit is set high when an interrupt is generated in the MMC Transmit Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
pub type MmctxisR = crate::BitReader<Mmctxis>;
impl MmctxisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mmctxis {
        match self.bits {
            false => Mmctxis::Inactive,
            true => Mmctxis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Mmctxis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Mmctxis::Active
    }
}
#[doc = "Field `mmctxis` writer - This bit is set high when an interrupt is generated in the MMC Transmit Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
pub type MmctxisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set high when an interrupt is generated in the MMC Receive Checksum Offload Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mmcrxipis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Mmcrxipis> for bool {
    #[inline(always)]
    fn from(variant: Mmcrxipis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mmcrxipis` reader - This bit is set high when an interrupt is generated in the MMC Receive Checksum Offload Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
pub type MmcrxipisR = crate::BitReader<Mmcrxipis>;
impl MmcrxipisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mmcrxipis {
        match self.bits {
            false => Mmcrxipis::Inactive,
            true => Mmcrxipis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Mmcrxipis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Mmcrxipis::Active
    }
}
#[doc = "Field `mmcrxipis` writer - This bit is set high when an interrupt is generated in the MMC Receive Checksum Offload Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
pub type MmcrxipisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when any of the following conditions is true: * The system time value equals or exceeds the value specified in the Target Time High and Low registers. * There is an overflow in the seconds register. * The Auxiliary snapshot trigger is asserted. This bit is cleared on reading Bit 0 of the Register 458 (Timestamp Status Register). When set, this bit indicates that the system time value is equal to or exceeds the value specified in the Target Time registers. In this mode, this bit is cleared after the completion of the read of this bit. In all other modes, this bit is reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tsis> for bool {
    #[inline(always)]
    fn from(variant: Tsis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsis` reader - This bit is set when any of the following conditions is true: * The system time value equals or exceeds the value specified in the Target Time High and Low registers. * There is an overflow in the seconds register. * The Auxiliary snapshot trigger is asserted. This bit is cleared on reading Bit 0 of the Register 458 (Timestamp Status Register). When set, this bit indicates that the system time value is equal to or exceeds the value specified in the Target Time registers. In this mode, this bit is cleared after the completion of the read of this bit. In all other modes, this bit is reserved."]
pub type TsisR = crate::BitReader<Tsis>;
impl TsisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsis {
        match self.bits {
            false => Tsis::Inactive,
            true => Tsis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tsis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tsis::Active
    }
}
#[doc = "Field `tsis` writer - This bit is set when any of the following conditions is true: * The system time value equals or exceeds the value specified in the Target Time High and Low registers. * There is an overflow in the seconds register. * The Auxiliary snapshot trigger is asserted. This bit is cleared on reading Bit 0 of the Register 458 (Timestamp Status Register). When set, this bit indicates that the system time value is equal to or exceeds the value specified in the Target Time registers. In this mode, this bit is cleared after the completion of the read of this bit. In all other modes, this bit is reserved."]
pub type TsisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set for any LPI state entry or exit in the MAC Transmitter or Receiver. This bit is cleared on reading Bit 0 of Register 12 (LPI Control and Status Register). In all other modes, this bit is reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lpiis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Lpiis> for bool {
    #[inline(always)]
    fn from(variant: Lpiis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lpiis` reader - This bit is set for any LPI state entry or exit in the MAC Transmitter or Receiver. This bit is cleared on reading Bit 0 of Register 12 (LPI Control and Status Register). In all other modes, this bit is reserved."]
pub type LpiisR = crate::BitReader<Lpiis>;
impl LpiisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lpiis {
        match self.bits {
            false => Lpiis::Inactive,
            true => Lpiis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Lpiis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Lpiis::Active
    }
}
#[doc = "Field `lpiis` writer - This bit is set for any LPI state entry or exit in the MAC Transmitter or Receiver. This bit is cleared on reading Bit 0 of Register 12 (LPI Control and Status Register). In all other modes, this bit is reserved."]
pub type LpiisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit is set because of any change in value of the Link Status of RGMII or SMII interface (Bit 3 in Register 54 (SGMII/RGMII/SMII Status Register)). This bit is cleared when you perform a read operation on the SGMII/RGMII/SMII Status Register."]
    #[inline(always)]
    pub fn rgsmiiis(&self) -> RgsmiiisR {
        RgsmiiisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is set because of any change in Link Status in the TBI, RTBI, or SGMII PHY interface (Bit 2 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation on the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
    #[inline(always)]
    pub fn pcslchgis(&self) -> PcslchgisR {
        PcslchgisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit is set when the Auto-negotiation is completed in the TBI, RTBI, or SGMII PHY interface (Bit 5 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation to the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
    #[inline(always)]
    pub fn pcsancis(&self) -> PcsancisR {
        PcsancisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set high when any of the Bits \\[7:5\\]
is set high and cleared only when all of these bits are low."]
    #[inline(always)]
    pub fn mmcis(&self) -> MmcisR {
        MmcisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set high when an interrupt is generated in the MMC Receive Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
    #[inline(always)]
    pub fn mmcrxis(&self) -> MmcrxisR {
        MmcrxisR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is set high when an interrupt is generated in the MMC Transmit Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
    #[inline(always)]
    pub fn mmctxis(&self) -> MmctxisR {
        MmctxisR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is set high when an interrupt is generated in the MMC Receive Checksum Offload Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
    #[inline(always)]
    pub fn mmcrxipis(&self) -> MmcrxipisR {
        MmcrxipisR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is set when any of the following conditions is true: * The system time value equals or exceeds the value specified in the Target Time High and Low registers. * There is an overflow in the seconds register. * The Auxiliary snapshot trigger is asserted. This bit is cleared on reading Bit 0 of the Register 458 (Timestamp Status Register). When set, this bit indicates that the system time value is equal to or exceeds the value specified in the Target Time registers. In this mode, this bit is cleared after the completion of the read of this bit. In all other modes, this bit is reserved."]
    #[inline(always)]
    pub fn tsis(&self) -> TsisR {
        TsisR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit is set for any LPI state entry or exit in the MAC Transmitter or Receiver. This bit is cleared on reading Bit 0 of Register 12 (LPI Control and Status Register). In all other modes, this bit is reserved."]
    #[inline(always)]
    pub fn lpiis(&self) -> LpiisR {
        LpiisR::new(((self.bits >> 10) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set because of any change in value of the Link Status of RGMII or SMII interface (Bit 3 in Register 54 (SGMII/RGMII/SMII Status Register)). This bit is cleared when you perform a read operation on the SGMII/RGMII/SMII Status Register."]
    #[inline(always)]
    #[must_use]
    pub fn rgsmiiis(&mut self) -> RgsmiiisW<GmacgrpInterruptStatusSpec> {
        RgsmiiisW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is set because of any change in Link Status in the TBI, RTBI, or SGMII PHY interface (Bit 2 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation on the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
    #[inline(always)]
    #[must_use]
    pub fn pcslchgis(&mut self) -> PcslchgisW<GmacgrpInterruptStatusSpec> {
        PcslchgisW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit is set when the Auto-negotiation is completed in the TBI, RTBI, or SGMII PHY interface (Bit 5 in Register 49 (AN Status Register)). This bit is cleared when you perform a read operation to the AN Status register. This bit is valid only when you select the SGMII PHY interface during operation."]
    #[inline(always)]
    #[must_use]
    pub fn pcsancis(&mut self) -> PcsancisW<GmacgrpInterruptStatusSpec> {
        PcsancisW::new(self, 2)
    }
    #[doc = "Bit 4 - This bit is set high when any of the Bits \\[7:5\\]
is set high and cleared only when all of these bits are low."]
    #[inline(always)]
    #[must_use]
    pub fn mmcis(&mut self) -> MmcisW<GmacgrpInterruptStatusSpec> {
        MmcisW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set high when an interrupt is generated in the MMC Receive Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
    #[inline(always)]
    #[must_use]
    pub fn mmcrxis(&mut self) -> MmcrxisW<GmacgrpInterruptStatusSpec> {
        MmcrxisW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is set high when an interrupt is generated in the MMC Transmit Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
    #[inline(always)]
    #[must_use]
    pub fn mmctxis(&mut self) -> MmctxisW<GmacgrpInterruptStatusSpec> {
        MmctxisW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is set high when an interrupt is generated in the MMC Receive Checksum Offload Interrupt Register. This bit is cleared when all the bits in this interrupt register are cleared."]
    #[inline(always)]
    #[must_use]
    pub fn mmcrxipis(&mut self) -> MmcrxipisW<GmacgrpInterruptStatusSpec> {
        MmcrxipisW::new(self, 7)
    }
    #[doc = "Bit 9 - This bit is set when any of the following conditions is true: * The system time value equals or exceeds the value specified in the Target Time High and Low registers. * There is an overflow in the seconds register. * The Auxiliary snapshot trigger is asserted. This bit is cleared on reading Bit 0 of the Register 458 (Timestamp Status Register). When set, this bit indicates that the system time value is equal to or exceeds the value specified in the Target Time registers. In this mode, this bit is cleared after the completion of the read of this bit. In all other modes, this bit is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn tsis(&mut self) -> TsisW<GmacgrpInterruptStatusSpec> {
        TsisW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit is set for any LPI state entry or exit in the MAC Transmitter or Receiver. This bit is cleared on reading Bit 0 of Register 12 (LPI Control and Status Register). In all other modes, this bit is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn lpiis(&mut self) -> LpiisW<GmacgrpInterruptStatusSpec> {
        LpiisW::new(self, 10)
    }
}
#[doc = "The Interrupt Status register identifies the events in the MAC that can generate interrupt. All interrupt events are generated only when the corresponding optional feature is enabled.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_interrupt_status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpInterruptStatusSpec;
impl crate::RegisterSpec for GmacgrpInterruptStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`gmacgrp_interrupt_status::R`](R) reader structure"]
impl crate::Readable for GmacgrpInterruptStatusSpec {}
#[doc = "`reset()` method sets gmacgrp_Interrupt_Status to value 0"]
impl crate::Resettable for GmacgrpInterruptStatusSpec {
    const RESET_VALUE: u32 = 0;
}
