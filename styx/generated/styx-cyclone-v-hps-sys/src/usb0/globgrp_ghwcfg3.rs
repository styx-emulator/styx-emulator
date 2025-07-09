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
#[doc = "Register `globgrp_ghwcfg3` reader"]
pub type R = crate::R<GlobgrpGhwcfg3Spec>;
#[doc = "Register `globgrp_ghwcfg3` writer"]
pub type W = crate::W<GlobgrpGhwcfg3Spec>;
#[doc = "Width variable from 11 to 19 bits.\n\nValue on reset: 8"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Xfersizewidth {
    #[doc = "0: `0`"]
    Width11 = 0,
    #[doc = "1: `1`"]
    Width12 = 1,
    #[doc = "2: `10`"]
    Width13 = 2,
    #[doc = "3: `11`"]
    Width14 = 3,
    #[doc = "4: `100`"]
    Width15 = 4,
    #[doc = "5: `101`"]
    Width16 = 5,
    #[doc = "6: `110`"]
    Width17 = 6,
    #[doc = "7: `111`"]
    Width18 = 7,
    #[doc = "8: `1000`"]
    Width19 = 8,
}
impl From<Xfersizewidth> for u8 {
    #[inline(always)]
    fn from(variant: Xfersizewidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Xfersizewidth {
    type Ux = u8;
}
#[doc = "Field `xfersizewidth` reader - Width variable from 11 to 19 bits."]
pub type XfersizewidthR = crate::FieldReader<Xfersizewidth>;
impl XfersizewidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Xfersizewidth> {
        match self.bits {
            0 => Some(Xfersizewidth::Width11),
            1 => Some(Xfersizewidth::Width12),
            2 => Some(Xfersizewidth::Width13),
            3 => Some(Xfersizewidth::Width14),
            4 => Some(Xfersizewidth::Width15),
            5 => Some(Xfersizewidth::Width16),
            6 => Some(Xfersizewidth::Width17),
            7 => Some(Xfersizewidth::Width18),
            8 => Some(Xfersizewidth::Width19),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_width11(&self) -> bool {
        *self == Xfersizewidth::Width11
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_width12(&self) -> bool {
        *self == Xfersizewidth::Width12
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_width13(&self) -> bool {
        *self == Xfersizewidth::Width13
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_width14(&self) -> bool {
        *self == Xfersizewidth::Width14
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_width15(&self) -> bool {
        *self == Xfersizewidth::Width15
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_width16(&self) -> bool {
        *self == Xfersizewidth::Width16
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_width17(&self) -> bool {
        *self == Xfersizewidth::Width17
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_width18(&self) -> bool {
        *self == Xfersizewidth::Width18
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_width19(&self) -> bool {
        *self == Xfersizewidth::Width19
    }
}
#[doc = "Field `xfersizewidth` writer - Width variable from 11 to 19 bits."]
pub type XfersizewidthW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "\n\nValue on reset: 6"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pktsizewidth {
    #[doc = "0: `0`"]
    Bits4 = 0,
    #[doc = "1: `1`"]
    Bits5 = 1,
    #[doc = "2: `10`"]
    Bits6 = 2,
    #[doc = "3: `11`"]
    Bits7 = 3,
    #[doc = "4: `100`"]
    Bits8 = 4,
    #[doc = "5: `101`"]
    Bits9 = 5,
    #[doc = "6: `110`"]
    Bits10 = 6,
}
impl From<Pktsizewidth> for u8 {
    #[inline(always)]
    fn from(variant: Pktsizewidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Pktsizewidth {
    type Ux = u8;
}
#[doc = "Field `pktsizewidth` reader - "]
pub type PktsizewidthR = crate::FieldReader<Pktsizewidth>;
impl PktsizewidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Pktsizewidth> {
        match self.bits {
            0 => Some(Pktsizewidth::Bits4),
            1 => Some(Pktsizewidth::Bits5),
            2 => Some(Pktsizewidth::Bits6),
            3 => Some(Pktsizewidth::Bits7),
            4 => Some(Pktsizewidth::Bits8),
            5 => Some(Pktsizewidth::Bits9),
            6 => Some(Pktsizewidth::Bits10),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_bits4(&self) -> bool {
        *self == Pktsizewidth::Bits4
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_bits5(&self) -> bool {
        *self == Pktsizewidth::Bits5
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_bits6(&self) -> bool {
        *self == Pktsizewidth::Bits6
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_bits7(&self) -> bool {
        *self == Pktsizewidth::Bits7
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_bits8(&self) -> bool {
        *self == Pktsizewidth::Bits8
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_bits9(&self) -> bool {
        *self == Pktsizewidth::Bits9
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_bits10(&self) -> bool {
        *self == Pktsizewidth::Bits10
    }
}
#[doc = "Field `pktsizewidth` writer - "]
pub type PktsizewidthW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "HNP and SRP Capable OTG (Device and Host)\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Otgen {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Otgen> for bool {
    #[inline(always)]
    fn from(variant: Otgen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `otgen` reader - HNP and SRP Capable OTG (Device and Host)"]
pub type OtgenR = crate::BitReader<Otgen>;
impl OtgenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Otgen> {
        match self.bits {
            true => Some(Otgen::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Otgen::Enabled
    }
}
#[doc = "Field `otgen` writer - HNP and SRP Capable OTG (Device and Host)"]
pub type OtgenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "I2C Interface not used.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cintsel {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<I2cintsel> for bool {
    #[inline(always)]
    fn from(variant: I2cintsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `i2cintsel` reader - I2C Interface not used."]
pub type I2cintselR = crate::BitReader<I2cintsel>;
impl I2cintselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<I2cintsel> {
        match self.bits {
            false => Some(I2cintsel::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == I2cintsel::Disabled
    }
}
#[doc = "Field `i2cintsel` writer - I2C Interface not used."]
pub type I2cintselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "ULPI PHY internal registers can be accessed by software using register reads/writes to otg\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vndctlsupt {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Vndctlsupt> for bool {
    #[inline(always)]
    fn from(variant: Vndctlsupt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vndctlsupt` reader - ULPI PHY internal registers can be accessed by software using register reads/writes to otg"]
pub type VndctlsuptR = crate::BitReader<Vndctlsupt>;
impl VndctlsuptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Vndctlsupt> {
        match self.bits {
            true => Some(Vndctlsupt::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Vndctlsupt::Enabled
    }
}
#[doc = "Field `vndctlsupt` writer - ULPI PHY internal registers can be accessed by software using register reads/writes to otg"]
pub type VndctlsuptW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "User ID register, GPIO interface ports, and SOF toggle and counter ports were removed.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Optfeature {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Optfeature> for bool {
    #[inline(always)]
    fn from(variant: Optfeature) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `optfeature` reader - User ID register, GPIO interface ports, and SOF toggle and counter ports were removed."]
pub type OptfeatureR = crate::BitReader<Optfeature>;
impl OptfeatureR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Optfeature> {
        match self.bits {
            false => Some(Optfeature::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Optfeature::Disabled
    }
}
#[doc = "Field `optfeature` writer - User ID register, GPIO interface ports, and SOF toggle and counter ports were removed."]
pub type OptfeatureW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Defines what reset type is used in the core.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rsttype {
    #[doc = "0: `0`"]
    Enabled = 0,
}
impl From<Rsttype> for bool {
    #[inline(always)]
    fn from(variant: Rsttype) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rsttype` reader - Defines what reset type is used in the core."]
pub type RsttypeR = crate::BitReader<Rsttype>;
impl RsttypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rsttype> {
        match self.bits {
            false => Some(Rsttype::Enabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rsttype::Enabled
    }
}
#[doc = "Field `rsttype` writer - Defines what reset type is used in the core."]
pub type RsttypeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "ADP logic support.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adpsupport {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Adpsupport> for bool {
    #[inline(always)]
    fn from(variant: Adpsupport) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `adpsupport` reader - ADP logic support."]
pub type AdpsupportR = crate::BitReader<Adpsupport>;
impl AdpsupportR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Adpsupport> {
        match self.bits {
            true => Some(Adpsupport::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Adpsupport::Enabled
    }
}
#[doc = "Field `adpsupport` writer - ADP logic support."]
pub type AdpsupportW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Supports HSIC and Non-HSIC Modes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hsicmode {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Hsicmode> for bool {
    #[inline(always)]
    fn from(variant: Hsicmode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hsicmode` reader - Supports HSIC and Non-HSIC Modes."]
pub type HsicmodeR = crate::BitReader<Hsicmode>;
impl HsicmodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Hsicmode> {
        match self.bits {
            false => Some(Hsicmode::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hsicmode::Disabled
    }
}
#[doc = "Field `hsicmode` writer - Supports HSIC and Non-HSIC Modes."]
pub type HsicmodeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Battery Charger Support.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bcsupport {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Bcsupport> for bool {
    #[inline(always)]
    fn from(variant: Bcsupport) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bcsupport` reader - Battery Charger Support."]
pub type BcsupportR = crate::BitReader<Bcsupport>;
impl BcsupportR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Bcsupport> {
        match self.bits {
            false => Some(Bcsupport::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Bcsupport::Disabled
    }
}
#[doc = "Field `bcsupport` writer - Battery Charger Support."]
pub type BcsupportW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "LPM Mode Enabled/Disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lpmmode {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Lpmmode> for bool {
    #[inline(always)]
    fn from(variant: Lpmmode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lpmmode` reader - LPM Mode Enabled/Disabled."]
pub type LpmmodeR = crate::BitReader<Lpmmode>;
impl LpmmodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Lpmmode> {
        match self.bits {
            false => Some(Lpmmode::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lpmmode::Disabled
    }
}
#[doc = "Field `lpmmode` writer - LPM Mode Enabled/Disabled."]
pub type LpmmodeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dfifodepth` reader - DFIFO Depth. This value is in terms of 35-bit words. Minimum value is 32 Maximum value is 8192"]
pub type DfifodepthR = crate::FieldReader<u16>;
#[doc = "Field `dfifodepth` writer - DFIFO Depth. This value is in terms of 35-bit words. Minimum value is 32 Maximum value is 8192"]
pub type DfifodepthW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:3 - Width variable from 11 to 19 bits."]
    #[inline(always)]
    pub fn xfersizewidth(&self) -> XfersizewidthR {
        XfersizewidthR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:6"]
    #[inline(always)]
    pub fn pktsizewidth(&self) -> PktsizewidthR {
        PktsizewidthR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bit 7 - HNP and SRP Capable OTG (Device and Host)"]
    #[inline(always)]
    pub fn otgen(&self) -> OtgenR {
        OtgenR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - I2C Interface not used."]
    #[inline(always)]
    pub fn i2cintsel(&self) -> I2cintselR {
        I2cintselR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - ULPI PHY internal registers can be accessed by software using register reads/writes to otg"]
    #[inline(always)]
    pub fn vndctlsupt(&self) -> VndctlsuptR {
        VndctlsuptR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - User ID register, GPIO interface ports, and SOF toggle and counter ports were removed."]
    #[inline(always)]
    pub fn optfeature(&self) -> OptfeatureR {
        OptfeatureR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Defines what reset type is used in the core."]
    #[inline(always)]
    pub fn rsttype(&self) -> RsttypeR {
        RsttypeR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - ADP logic support."]
    #[inline(always)]
    pub fn adpsupport(&self) -> AdpsupportR {
        AdpsupportR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Supports HSIC and Non-HSIC Modes."]
    #[inline(always)]
    pub fn hsicmode(&self) -> HsicmodeR {
        HsicmodeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Battery Charger Support."]
    #[inline(always)]
    pub fn bcsupport(&self) -> BcsupportR {
        BcsupportR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - LPM Mode Enabled/Disabled."]
    #[inline(always)]
    pub fn lpmmode(&self) -> LpmmodeR {
        LpmmodeR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:31 - DFIFO Depth. This value is in terms of 35-bit words. Minimum value is 32 Maximum value is 8192"]
    #[inline(always)]
    pub fn dfifodepth(&self) -> DfifodepthR {
        DfifodepthR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:3 - Width variable from 11 to 19 bits."]
    #[inline(always)]
    #[must_use]
    pub fn xfersizewidth(&mut self) -> XfersizewidthW<GlobgrpGhwcfg3Spec> {
        XfersizewidthW::new(self, 0)
    }
    #[doc = "Bits 4:6"]
    #[inline(always)]
    #[must_use]
    pub fn pktsizewidth(&mut self) -> PktsizewidthW<GlobgrpGhwcfg3Spec> {
        PktsizewidthW::new(self, 4)
    }
    #[doc = "Bit 7 - HNP and SRP Capable OTG (Device and Host)"]
    #[inline(always)]
    #[must_use]
    pub fn otgen(&mut self) -> OtgenW<GlobgrpGhwcfg3Spec> {
        OtgenW::new(self, 7)
    }
    #[doc = "Bit 8 - I2C Interface not used."]
    #[inline(always)]
    #[must_use]
    pub fn i2cintsel(&mut self) -> I2cintselW<GlobgrpGhwcfg3Spec> {
        I2cintselW::new(self, 8)
    }
    #[doc = "Bit 9 - ULPI PHY internal registers can be accessed by software using register reads/writes to otg"]
    #[inline(always)]
    #[must_use]
    pub fn vndctlsupt(&mut self) -> VndctlsuptW<GlobgrpGhwcfg3Spec> {
        VndctlsuptW::new(self, 9)
    }
    #[doc = "Bit 10 - User ID register, GPIO interface ports, and SOF toggle and counter ports were removed."]
    #[inline(always)]
    #[must_use]
    pub fn optfeature(&mut self) -> OptfeatureW<GlobgrpGhwcfg3Spec> {
        OptfeatureW::new(self, 10)
    }
    #[doc = "Bit 11 - Defines what reset type is used in the core."]
    #[inline(always)]
    #[must_use]
    pub fn rsttype(&mut self) -> RsttypeW<GlobgrpGhwcfg3Spec> {
        RsttypeW::new(self, 11)
    }
    #[doc = "Bit 12 - ADP logic support."]
    #[inline(always)]
    #[must_use]
    pub fn adpsupport(&mut self) -> AdpsupportW<GlobgrpGhwcfg3Spec> {
        AdpsupportW::new(self, 12)
    }
    #[doc = "Bit 13 - Supports HSIC and Non-HSIC Modes."]
    #[inline(always)]
    #[must_use]
    pub fn hsicmode(&mut self) -> HsicmodeW<GlobgrpGhwcfg3Spec> {
        HsicmodeW::new(self, 13)
    }
    #[doc = "Bit 14 - Battery Charger Support."]
    #[inline(always)]
    #[must_use]
    pub fn bcsupport(&mut self) -> BcsupportW<GlobgrpGhwcfg3Spec> {
        BcsupportW::new(self, 14)
    }
    #[doc = "Bit 15 - LPM Mode Enabled/Disabled."]
    #[inline(always)]
    #[must_use]
    pub fn lpmmode(&mut self) -> LpmmodeW<GlobgrpGhwcfg3Spec> {
        LpmmodeW::new(self, 15)
    }
    #[doc = "Bits 16:31 - DFIFO Depth. This value is in terms of 35-bit words. Minimum value is 32 Maximum value is 8192"]
    #[inline(always)]
    #[must_use]
    pub fn dfifodepth(&mut self) -> DfifodepthW<GlobgrpGhwcfg3Spec> {
        DfifodepthW::new(self, 16)
    }
}
#[doc = "This register contains the configuration options.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGhwcfg3Spec;
impl crate::RegisterSpec for GlobgrpGhwcfg3Spec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`globgrp_ghwcfg3::R`](R) reader structure"]
impl crate::Readable for GlobgrpGhwcfg3Spec {}
#[doc = "`reset()` method sets globgrp_ghwcfg3 to value 0x1f80_02e8"]
impl crate::Resettable for GlobgrpGhwcfg3Spec {
    const RESET_VALUE: u32 = 0x1f80_02e8;
}
