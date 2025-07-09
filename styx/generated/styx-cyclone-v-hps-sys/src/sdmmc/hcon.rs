// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `hcon` reader"]
pub type R = crate::R<HconSpec>;
#[doc = "Register `hcon` writer"]
pub type W = crate::W<HconSpec>;
#[doc = "Supported card types\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ct {
    #[doc = "1: `1`"]
    Sdmmc = 1,
}
impl From<Ct> for bool {
    #[inline(always)]
    fn from(variant: Ct) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ct` reader - Supported card types"]
pub type CtR = crate::BitReader<Ct>;
impl CtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ct> {
        match self.bits {
            true => Some(Ct::Sdmmc),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sdmmc(&self) -> bool {
        *self == Ct::Sdmmc
    }
}
#[doc = "Field `ct` writer - Supported card types"]
pub type CtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Maximum number of cards less one\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Nc {
    #[doc = "0: `0`"]
    Numcard = 0,
}
impl From<Nc> for u8 {
    #[inline(always)]
    fn from(variant: Nc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Nc {
    type Ux = u8;
}
#[doc = "Field `nc` reader - Maximum number of cards less one"]
pub type NcR = crate::FieldReader<Nc>;
impl NcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Nc> {
        match self.bits {
            0 => Some(Nc::Numcard),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_numcard(&self) -> bool {
        *self == Nc::Numcard
    }
}
#[doc = "Field `nc` writer - Maximum number of cards less one"]
pub type NcW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Slave bus type.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hbus {
    #[doc = "0: `0`"]
    Apb = 0,
}
impl From<Hbus> for bool {
    #[inline(always)]
    fn from(variant: Hbus) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hbus` reader - Slave bus type."]
pub type HbusR = crate::BitReader<Hbus>;
impl HbusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Hbus> {
        match self.bits {
            false => Some(Hbus::Apb),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_apb(&self) -> bool {
        *self == Hbus::Apb
    }
}
#[doc = "Field `hbus` writer - Slave bus type."]
pub type HbusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Slave bus data width\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Hdatawidth {
    #[doc = "1: `1`"]
    Width32bits = 1,
}
impl From<Hdatawidth> for u8 {
    #[inline(always)]
    fn from(variant: Hdatawidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Hdatawidth {
    type Ux = u8;
}
#[doc = "Field `hdatawidth` reader - Slave bus data width"]
pub type HdatawidthR = crate::FieldReader<Hdatawidth>;
impl HdatawidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Hdatawidth> {
        match self.bits {
            1 => Some(Hdatawidth::Width32bits),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_width32bits(&self) -> bool {
        *self == Hdatawidth::Width32bits
    }
}
#[doc = "Field `hdatawidth` writer - Slave bus data width"]
pub type HdatawidthW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Slave bus address width less one\n\nValue on reset: 12"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Haddrwidth {
    #[doc = "12: `1100`"]
    Width13bits = 12,
}
impl From<Haddrwidth> for u8 {
    #[inline(always)]
    fn from(variant: Haddrwidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Haddrwidth {
    type Ux = u8;
}
#[doc = "Field `haddrwidth` reader - Slave bus address width less one"]
pub type HaddrwidthR = crate::FieldReader<Haddrwidth>;
impl HaddrwidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Haddrwidth> {
        match self.bits {
            12 => Some(Haddrwidth::Width13bits),
            _ => None,
        }
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_width13bits(&self) -> bool {
        *self == Haddrwidth::Width13bits
    }
}
#[doc = "Field `haddrwidth` writer - Slave bus address width less one"]
pub type HaddrwidthW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "DMA interface type\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dmaintf {
    #[doc = "0: `0`"]
    None = 0,
}
impl From<Dmaintf> for u8 {
    #[inline(always)]
    fn from(variant: Dmaintf) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dmaintf {
    type Ux = u8;
}
#[doc = "Field `dmaintf` reader - DMA interface type"]
pub type DmaintfR = crate::FieldReader<Dmaintf>;
impl DmaintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dmaintf> {
        match self.bits {
            0 => Some(Dmaintf::None),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_none(&self) -> bool {
        *self == Dmaintf::None
    }
}
#[doc = "Field `dmaintf` writer - DMA interface type"]
pub type DmaintfW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Encodes bit width of external DMA controller interface. Doesn't apply to the SD/MMC because it has no external DMA controller interface.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dmadatawidth {
    #[doc = "1: `1`"]
    Width32bits = 1,
}
impl From<Dmadatawidth> for u8 {
    #[inline(always)]
    fn from(variant: Dmadatawidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dmadatawidth {
    type Ux = u8;
}
#[doc = "Field `dmadatawidth` reader - Encodes bit width of external DMA controller interface. Doesn't apply to the SD/MMC because it has no external DMA controller interface."]
pub type DmadatawidthR = crate::FieldReader<Dmadatawidth>;
impl DmadatawidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dmadatawidth> {
        match self.bits {
            1 => Some(Dmadatawidth::Width32bits),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_width32bits(&self) -> bool {
        *self == Dmadatawidth::Width32bits
    }
}
#[doc = "Field `dmadatawidth` writer - Encodes bit width of external DMA controller interface. Doesn't apply to the SD/MMC because it has no external DMA controller interface."]
pub type DmadatawidthW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "FIFO RAM location\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rios {
    #[doc = "0: `0`"]
    Outside = 0,
}
impl From<Rios> for bool {
    #[inline(always)]
    fn from(variant: Rios) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rios` reader - FIFO RAM location"]
pub type RiosR = crate::BitReader<Rios>;
impl RiosR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rios> {
        match self.bits {
            false => Some(Rios::Outside),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_outside(&self) -> bool {
        *self == Rios::Outside
    }
}
#[doc = "Field `rios` writer - FIFO RAM location"]
pub type RiosW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Implement hold register\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ihr {
    #[doc = "1: `1`"]
    Implemented = 1,
}
impl From<Ihr> for bool {
    #[inline(always)]
    fn from(variant: Ihr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ihr` reader - Implement hold register"]
pub type IhrR = crate::BitReader<Ihr>;
impl IhrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ihr> {
        match self.bits {
            true => Some(Ihr::Implemented),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_implemented(&self) -> bool {
        *self == Ihr::Implemented
    }
}
#[doc = "Field `ihr` writer - Implement hold register"]
pub type IhrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Clock False Path\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scfp {
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<Scfp> for bool {
    #[inline(always)]
    fn from(variant: Scfp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `scfp` reader - Clock False Path"]
pub type ScfpR = crate::BitReader<Scfp>;
impl ScfpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Scfp> {
        match self.bits {
            true => Some(Scfp::Set),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == Scfp::Set
    }
}
#[doc = "Field `scfp` writer - Clock False Path"]
pub type ScfpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Number of clock dividers less one\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ncd {
    #[doc = "0: `0`"]
    Onediv = 0,
}
impl From<Ncd> for u8 {
    #[inline(always)]
    fn from(variant: Ncd) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ncd {
    type Ux = u8;
}
#[doc = "Field `ncd` reader - Number of clock dividers less one"]
pub type NcdR = crate::FieldReader<Ncd>;
impl NcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ncd> {
        match self.bits {
            0 => Some(Ncd::Onediv),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_onediv(&self) -> bool {
        *self == Ncd::Onediv
    }
}
#[doc = "Field `ncd` writer - Number of clock dividers less one"]
pub type NcdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Area optimized\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aro {
    #[doc = "0: `0`"]
    Notoptforarea = 0,
}
impl From<Aro> for bool {
    #[inline(always)]
    fn from(variant: Aro) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `aro` reader - Area optimized"]
pub type AroR = crate::BitReader<Aro>;
impl AroR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Aro> {
        match self.bits {
            false => Some(Aro::Notoptforarea),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notoptforarea(&self) -> bool {
        *self == Aro::Notoptforarea
    }
}
#[doc = "Field `aro` writer - Area optimized"]
pub type AroW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Supported card types"]
    #[inline(always)]
    pub fn ct(&self) -> CtR {
        CtR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:5 - Maximum number of cards less one"]
    #[inline(always)]
    pub fn nc(&self) -> NcR {
        NcR::new(((self.bits >> 1) & 0x1f) as u8)
    }
    #[doc = "Bit 6 - Slave bus type."]
    #[inline(always)]
    pub fn hbus(&self) -> HbusR {
        HbusR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 7:9 - Slave bus data width"]
    #[inline(always)]
    pub fn hdatawidth(&self) -> HdatawidthR {
        HdatawidthR::new(((self.bits >> 7) & 7) as u8)
    }
    #[doc = "Bits 10:15 - Slave bus address width less one"]
    #[inline(always)]
    pub fn haddrwidth(&self) -> HaddrwidthR {
        HaddrwidthR::new(((self.bits >> 10) & 0x3f) as u8)
    }
    #[doc = "Bits 16:17 - DMA interface type"]
    #[inline(always)]
    pub fn dmaintf(&self) -> DmaintfR {
        DmaintfR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 18:20 - Encodes bit width of external DMA controller interface. Doesn't apply to the SD/MMC because it has no external DMA controller interface."]
    #[inline(always)]
    pub fn dmadatawidth(&self) -> DmadatawidthR {
        DmadatawidthR::new(((self.bits >> 18) & 7) as u8)
    }
    #[doc = "Bit 21 - FIFO RAM location"]
    #[inline(always)]
    pub fn rios(&self) -> RiosR {
        RiosR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Implement hold register"]
    #[inline(always)]
    pub fn ihr(&self) -> IhrR {
        IhrR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Clock False Path"]
    #[inline(always)]
    pub fn scfp(&self) -> ScfpR {
        ScfpR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:25 - Number of clock dividers less one"]
    #[inline(always)]
    pub fn ncd(&self) -> NcdR {
        NcdR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bit 26 - Area optimized"]
    #[inline(always)]
    pub fn aro(&self) -> AroR {
        AroR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Supported card types"]
    #[inline(always)]
    #[must_use]
    pub fn ct(&mut self) -> CtW<HconSpec> {
        CtW::new(self, 0)
    }
    #[doc = "Bits 1:5 - Maximum number of cards less one"]
    #[inline(always)]
    #[must_use]
    pub fn nc(&mut self) -> NcW<HconSpec> {
        NcW::new(self, 1)
    }
    #[doc = "Bit 6 - Slave bus type."]
    #[inline(always)]
    #[must_use]
    pub fn hbus(&mut self) -> HbusW<HconSpec> {
        HbusW::new(self, 6)
    }
    #[doc = "Bits 7:9 - Slave bus data width"]
    #[inline(always)]
    #[must_use]
    pub fn hdatawidth(&mut self) -> HdatawidthW<HconSpec> {
        HdatawidthW::new(self, 7)
    }
    #[doc = "Bits 10:15 - Slave bus address width less one"]
    #[inline(always)]
    #[must_use]
    pub fn haddrwidth(&mut self) -> HaddrwidthW<HconSpec> {
        HaddrwidthW::new(self, 10)
    }
    #[doc = "Bits 16:17 - DMA interface type"]
    #[inline(always)]
    #[must_use]
    pub fn dmaintf(&mut self) -> DmaintfW<HconSpec> {
        DmaintfW::new(self, 16)
    }
    #[doc = "Bits 18:20 - Encodes bit width of external DMA controller interface. Doesn't apply to the SD/MMC because it has no external DMA controller interface."]
    #[inline(always)]
    #[must_use]
    pub fn dmadatawidth(&mut self) -> DmadatawidthW<HconSpec> {
        DmadatawidthW::new(self, 18)
    }
    #[doc = "Bit 21 - FIFO RAM location"]
    #[inline(always)]
    #[must_use]
    pub fn rios(&mut self) -> RiosW<HconSpec> {
        RiosW::new(self, 21)
    }
    #[doc = "Bit 22 - Implement hold register"]
    #[inline(always)]
    #[must_use]
    pub fn ihr(&mut self) -> IhrW<HconSpec> {
        IhrW::new(self, 22)
    }
    #[doc = "Bit 23 - Clock False Path"]
    #[inline(always)]
    #[must_use]
    pub fn scfp(&mut self) -> ScfpW<HconSpec> {
        ScfpW::new(self, 23)
    }
    #[doc = "Bits 24:25 - Number of clock dividers less one"]
    #[inline(always)]
    #[must_use]
    pub fn ncd(&mut self) -> NcdW<HconSpec> {
        NcdW::new(self, 24)
    }
    #[doc = "Bit 26 - Area optimized"]
    #[inline(always)]
    #[must_use]
    pub fn aro(&mut self) -> AroW<HconSpec> {
        AroW::new(self, 26)
    }
}
#[doc = "Hardware configurations registers. Register can be used to develop configuration-independent software drivers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hcon::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HconSpec;
impl crate::RegisterSpec for HconSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`hcon::R`](R) reader structure"]
impl crate::Readable for HconSpec {}
#[doc = "`reset()` method sets hcon to value 0x00c4_3081"]
impl crate::Resettable for HconSpec {
    const RESET_VALUE: u32 = 0x00c4_3081;
}
