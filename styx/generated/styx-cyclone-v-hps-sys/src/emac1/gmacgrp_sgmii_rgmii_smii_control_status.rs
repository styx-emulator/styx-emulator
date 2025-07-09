// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_SGMII_RGMII_SMII_Control_Status` reader"]
pub type R = crate::R<GmacgrpSgmiiRgmiiSmiiControlStatusSpec>;
#[doc = "Register `gmacgrp_SGMII_RGMII_SMII_Control_Status` writer"]
pub type W = crate::W<GmacgrpSgmiiRgmiiSmiiControlStatusSpec>;
#[doc = "This bit indicates the current mode of operation of the link\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lnkmod {
    #[doc = "0: `0`"]
    Halfdup = 0,
    #[doc = "1: `1`"]
    Fulldup = 1,
}
impl From<Lnkmod> for bool {
    #[inline(always)]
    fn from(variant: Lnkmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lnkmod` reader - This bit indicates the current mode of operation of the link"]
pub type LnkmodR = crate::BitReader<Lnkmod>;
impl LnkmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lnkmod {
        match self.bits {
            false => Lnkmod::Halfdup,
            true => Lnkmod::Fulldup,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_halfdup(&self) -> bool {
        *self == Lnkmod::Halfdup
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fulldup(&self) -> bool {
        *self == Lnkmod::Fulldup
    }
}
#[doc = "Field `lnkmod` writer - This bit indicates the current mode of operation of the link"]
pub type LnkmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit indicates the current speed of the link. Bit 2 is reserved when the MAC is configured for the SMII PHY interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Lnkspeed {
    #[doc = "0: `0`"]
    Speed2point5mhz = 0,
    #[doc = "1: `1`"]
    Speed25mhz = 1,
    #[doc = "2: `10`"]
    Speed125mhz = 2,
}
impl From<Lnkspeed> for u8 {
    #[inline(always)]
    fn from(variant: Lnkspeed) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Lnkspeed {
    type Ux = u8;
}
#[doc = "Field `lnkspeed` reader - This bit indicates the current speed of the link. Bit 2 is reserved when the MAC is configured for the SMII PHY interface."]
pub type LnkspeedR = crate::FieldReader<Lnkspeed>;
impl LnkspeedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Lnkspeed> {
        match self.bits {
            0 => Some(Lnkspeed::Speed2point5mhz),
            1 => Some(Lnkspeed::Speed25mhz),
            2 => Some(Lnkspeed::Speed125mhz),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_speed2point5mhz(&self) -> bool {
        *self == Lnkspeed::Speed2point5mhz
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_speed25mhz(&self) -> bool {
        *self == Lnkspeed::Speed25mhz
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_speed125mhz(&self) -> bool {
        *self == Lnkspeed::Speed125mhz
    }
}
#[doc = "Field `lnkspeed` writer - This bit indicates the current speed of the link. Bit 2 is reserved when the MAC is configured for the SMII PHY interface."]
pub type LnkspeedW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "This bit indicates whether the link is up (1'b1) or down (1'b0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lnksts {
    #[doc = "0: `0`"]
    Linkdown = 0,
    #[doc = "1: `1`"]
    Linkup = 1,
}
impl From<Lnksts> for bool {
    #[inline(always)]
    fn from(variant: Lnksts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lnksts` reader - This bit indicates whether the link is up (1'b1) or down (1'b0)."]
pub type LnkstsR = crate::BitReader<Lnksts>;
impl LnkstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lnksts {
        match self.bits {
            false => Lnksts::Linkdown,
            true => Lnksts::Linkup,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_linkdown(&self) -> bool {
        *self == Lnksts::Linkdown
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_linkup(&self) -> bool {
        *self == Lnksts::Linkup
    }
}
#[doc = "Field `lnksts` writer - This bit indicates whether the link is up (1'b1) or down (1'b0)."]
pub type LnkstsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit indicates the current mode of operation of the link"]
    #[inline(always)]
    pub fn lnkmod(&self) -> LnkmodR {
        LnkmodR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - This bit indicates the current speed of the link. Bit 2 is reserved when the MAC is configured for the SMII PHY interface."]
    #[inline(always)]
    pub fn lnkspeed(&self) -> LnkspeedR {
        LnkspeedR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 3 - This bit indicates whether the link is up (1'b1) or down (1'b0)."]
    #[inline(always)]
    pub fn lnksts(&self) -> LnkstsR {
        LnkstsR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit indicates the current mode of operation of the link"]
    #[inline(always)]
    #[must_use]
    pub fn lnkmod(&mut self) -> LnkmodW<GmacgrpSgmiiRgmiiSmiiControlStatusSpec> {
        LnkmodW::new(self, 0)
    }
    #[doc = "Bits 1:2 - This bit indicates the current speed of the link. Bit 2 is reserved when the MAC is configured for the SMII PHY interface."]
    #[inline(always)]
    #[must_use]
    pub fn lnkspeed(&mut self) -> LnkspeedW<GmacgrpSgmiiRgmiiSmiiControlStatusSpec> {
        LnkspeedW::new(self, 1)
    }
    #[doc = "Bit 3 - This bit indicates whether the link is up (1'b1) or down (1'b0)."]
    #[inline(always)]
    #[must_use]
    pub fn lnksts(&mut self) -> LnkstsW<GmacgrpSgmiiRgmiiSmiiControlStatusSpec> {
        LnkstsW::new(self, 3)
    }
}
#[doc = "The SGMII/RGMII/SMII Status register indicates the status signals received by the RGMII interface (selected at reset) from the PHY.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_sgmii_rgmii_smii_control_status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSgmiiRgmiiSmiiControlStatusSpec;
impl crate::RegisterSpec for GmacgrpSgmiiRgmiiSmiiControlStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 216u64;
}
#[doc = "`read()` method returns [`gmacgrp_sgmii_rgmii_smii_control_status::R`](R) reader structure"]
impl crate::Readable for GmacgrpSgmiiRgmiiSmiiControlStatusSpec {}
#[doc = "`reset()` method sets gmacgrp_SGMII_RGMII_SMII_Control_Status to value 0"]
impl crate::Resettable for GmacgrpSgmiiRgmiiSmiiControlStatusSpec {
    const RESET_VALUE: u32 = 0;
}
