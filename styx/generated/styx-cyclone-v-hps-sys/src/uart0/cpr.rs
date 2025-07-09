// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `cpr` reader"]
pub type R = crate::R<CprSpec>;
#[doc = "Register `cpr` writer"]
pub type W = crate::W<CprSpec>;
#[doc = "Fixed to support an ABP data bus width of 32-bits.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Apbdatawidth {
    #[doc = "2: `10`"]
    Width32bits = 2,
}
impl From<Apbdatawidth> for u8 {
    #[inline(always)]
    fn from(variant: Apbdatawidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Apbdatawidth {
    type Ux = u8;
}
#[doc = "Field `apbdatawidth` reader - Fixed to support an ABP data bus width of 32-bits."]
pub type ApbdatawidthR = crate::FieldReader<Apbdatawidth>;
impl ApbdatawidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Apbdatawidth> {
        match self.bits {
            2 => Some(Apbdatawidth::Width32bits),
            _ => None,
        }
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_width32bits(&self) -> bool {
        *self == Apbdatawidth::Width32bits
    }
}
#[doc = "Field `apbdatawidth` writer - Fixed to support an ABP data bus width of 32-bits."]
pub type ApbdatawidthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Allows auto flow control.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfceMode {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<AfceMode> for bool {
    #[inline(always)]
    fn from(variant: AfceMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `afce_mode` reader - Allows auto flow control."]
pub type AfceModeR = crate::BitReader<AfceMode>;
impl AfceModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<AfceMode> {
        match self.bits {
            true => Some(AfceMode::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == AfceMode::Enabled
    }
}
#[doc = "Field `afce_mode` writer - Allows auto flow control."]
pub type AfceModeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Programmable Transmitter Hold Register Empty interrupt\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreMode {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<ThreMode> for bool {
    #[inline(always)]
    fn from(variant: ThreMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `thre_mode` reader - Programmable Transmitter Hold Register Empty interrupt"]
pub type ThreModeR = crate::BitReader<ThreMode>;
impl ThreModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<ThreMode> {
        match self.bits {
            true => Some(ThreMode::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == ThreMode::Enabled
    }
}
#[doc = "Field `thre_mode` writer - Programmable Transmitter Hold Register Empty interrupt"]
pub type ThreModeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Sir mode not used in this application.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SirMode {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<SirMode> for bool {
    #[inline(always)]
    fn from(variant: SirMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sir_mode` reader - Sir mode not used in this application."]
pub type SirModeR = crate::BitReader<SirMode>;
impl SirModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<SirMode> {
        match self.bits {
            false => Some(SirMode::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == SirMode::Disabled
    }
}
#[doc = "Field `sir_mode` writer - Sir mode not used in this application."]
pub type SirModeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "LP Sir Mode not used in this application.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SirLpMode {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<SirLpMode> for bool {
    #[inline(always)]
    fn from(variant: SirLpMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sir_lp_mode` reader - LP Sir Mode not used in this application."]
pub type SirLpModeR = crate::BitReader<SirLpMode>;
impl SirLpModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<SirLpMode> {
        match self.bits {
            false => Some(SirLpMode::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == SirLpMode::Disabled
    }
}
#[doc = "Field `sir_lp_mode` writer - LP Sir Mode not used in this application."]
pub type SirLpModeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Configures the uart to include fifo status register, shadow registers and encoded parameter register.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdditionalFeat {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<AdditionalFeat> for bool {
    #[inline(always)]
    fn from(variant: AdditionalFeat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `additional_feat` reader - Configures the uart to include fifo status register, shadow registers and encoded parameter register."]
pub type AdditionalFeatR = crate::BitReader<AdditionalFeat>;
impl AdditionalFeatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<AdditionalFeat> {
        match self.bits {
            true => Some(AdditionalFeat::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == AdditionalFeat::Enabled
    }
}
#[doc = "Field `additional_feat` writer - Configures the uart to include fifo status register, shadow registers and encoded parameter register."]
pub type AdditionalFeatW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Configures the peripheral to have a programmable FIFO access mode. This is used for test purposes, to allow the receiver FIFO to be written and the transmit FIFO to be read when FIFOs are implemented and enabled.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoAccess {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<FifoAccess> for bool {
    #[inline(always)]
    fn from(variant: FifoAccess) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_access` reader - Configures the peripheral to have a programmable FIFO access mode. This is used for test purposes, to allow the receiver FIFO to be written and the transmit FIFO to be read when FIFOs are implemented and enabled."]
pub type FifoAccessR = crate::BitReader<FifoAccess>;
impl FifoAccessR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<FifoAccess> {
        match self.bits {
            true => Some(FifoAccess::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == FifoAccess::Enabled
    }
}
#[doc = "Field `fifo_access` writer - Configures the peripheral to have a programmable FIFO access mode. This is used for test purposes, to allow the receiver FIFO to be written and the transmit FIFO to be read when FIFOs are implemented and enabled."]
pub type FifoAccessW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Configures the peripheral to have three additional FIFO status registers.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoStat {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<FifoStat> for bool {
    #[inline(always)]
    fn from(variant: FifoStat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_stat` reader - Configures the peripheral to have three additional FIFO status registers."]
pub type FifoStatR = crate::BitReader<FifoStat>;
impl FifoStatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<FifoStat> {
        match self.bits {
            true => Some(FifoStat::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == FifoStat::Enabled
    }
}
#[doc = "Field `fifo_stat` writer - Configures the peripheral to have three additional FIFO status registers."]
pub type FifoStatW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Configures the peripheral to have seven additional registers that shadow some of the existing register bits that are regularly modified by software. These can be used to reduce the software overhead that is introduced by having to perform read-modify writes.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shadow {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Shadow> for bool {
    #[inline(always)]
    fn from(variant: Shadow) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `shadow` reader - Configures the peripheral to have seven additional registers that shadow some of the existing register bits that are regularly modified by software. These can be used to reduce the software overhead that is introduced by having to perform read-modify writes."]
pub type ShadowR = crate::BitReader<Shadow>;
impl ShadowR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Shadow> {
        match self.bits {
            true => Some(Shadow::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Shadow::Enabled
    }
}
#[doc = "Field `shadow` writer - Configures the peripheral to have seven additional registers that shadow some of the existing register bits that are regularly modified by software. These can be used to reduce the software overhead that is introduced by having to perform read-modify writes."]
pub type ShadowW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Configures the peripheral to have a configuration identification register.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UartAddEncodedParam {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<UartAddEncodedParam> for bool {
    #[inline(always)]
    fn from(variant: UartAddEncodedParam) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `uart_add_encoded_param` reader - Configures the peripheral to have a configuration identification register."]
pub type UartAddEncodedParamR = crate::BitReader<UartAddEncodedParam>;
impl UartAddEncodedParamR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<UartAddEncodedParam> {
        match self.bits {
            true => Some(UartAddEncodedParam::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == UartAddEncodedParam::Enabled
    }
}
#[doc = "Field `uart_add_encoded_param` writer - Configures the peripheral to have a configuration identification register."]
pub type UartAddEncodedParamW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Configures the peripheral to have four additional DMA signals on the interface.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaExtra {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<DmaExtra> for bool {
    #[inline(always)]
    fn from(variant: DmaExtra) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dma_extra` reader - Configures the peripheral to have four additional DMA signals on the interface."]
pub type DmaExtraR = crate::BitReader<DmaExtra>;
impl DmaExtraR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<DmaExtra> {
        match self.bits {
            true => Some(DmaExtra::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == DmaExtra::Enabled
    }
}
#[doc = "Field `dma_extra` writer - Configures the peripheral to have four additional DMA signals on the interface."]
pub type DmaExtraW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Receiver and Transmitter FIFO depth in bytes.\n\nValue on reset: 55"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FifoMode {
    #[doc = "128: `10000000`"]
    Fifo128bytes = 128,
}
impl From<FifoMode> for u8 {
    #[inline(always)]
    fn from(variant: FifoMode) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for FifoMode {
    type Ux = u8;
}
#[doc = "Field `fifo_mode` reader - Receiver and Transmitter FIFO depth in bytes."]
pub type FifoModeR = crate::FieldReader<FifoMode>;
impl FifoModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<FifoMode> {
        match self.bits {
            128 => Some(FifoMode::Fifo128bytes),
            _ => None,
        }
    }
    #[doc = "`10000000`"]
    #[inline(always)]
    pub fn is_fifo128bytes(&self) -> bool {
        *self == FifoMode::Fifo128bytes
    }
}
#[doc = "Field `fifo_mode` writer - Receiver and Transmitter FIFO depth in bytes."]
pub type FifoModeW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:1 - Fixed to support an ABP data bus width of 32-bits."]
    #[inline(always)]
    pub fn apbdatawidth(&self) -> ApbdatawidthR {
        ApbdatawidthR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 4 - Allows auto flow control."]
    #[inline(always)]
    pub fn afce_mode(&self) -> AfceModeR {
        AfceModeR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Programmable Transmitter Hold Register Empty interrupt"]
    #[inline(always)]
    pub fn thre_mode(&self) -> ThreModeR {
        ThreModeR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Sir mode not used in this application."]
    #[inline(always)]
    pub fn sir_mode(&self) -> SirModeR {
        SirModeR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - LP Sir Mode not used in this application."]
    #[inline(always)]
    pub fn sir_lp_mode(&self) -> SirLpModeR {
        SirLpModeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Configures the uart to include fifo status register, shadow registers and encoded parameter register."]
    #[inline(always)]
    pub fn additional_feat(&self) -> AdditionalFeatR {
        AdditionalFeatR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Configures the peripheral to have a programmable FIFO access mode. This is used for test purposes, to allow the receiver FIFO to be written and the transmit FIFO to be read when FIFOs are implemented and enabled."]
    #[inline(always)]
    pub fn fifo_access(&self) -> FifoAccessR {
        FifoAccessR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Configures the peripheral to have three additional FIFO status registers."]
    #[inline(always)]
    pub fn fifo_stat(&self) -> FifoStatR {
        FifoStatR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Configures the peripheral to have seven additional registers that shadow some of the existing register bits that are regularly modified by software. These can be used to reduce the software overhead that is introduced by having to perform read-modify writes."]
    #[inline(always)]
    pub fn shadow(&self) -> ShadowR {
        ShadowR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Configures the peripheral to have a configuration identification register."]
    #[inline(always)]
    pub fn uart_add_encoded_param(&self) -> UartAddEncodedParamR {
        UartAddEncodedParamR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Configures the peripheral to have four additional DMA signals on the interface."]
    #[inline(always)]
    pub fn dma_extra(&self) -> DmaExtraR {
        DmaExtraR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 16:23 - Receiver and Transmitter FIFO depth in bytes."]
    #[inline(always)]
    pub fn fifo_mode(&self) -> FifoModeR {
        FifoModeR::new(((self.bits >> 16) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Fixed to support an ABP data bus width of 32-bits."]
    #[inline(always)]
    #[must_use]
    pub fn apbdatawidth(&mut self) -> ApbdatawidthW<CprSpec> {
        ApbdatawidthW::new(self, 0)
    }
    #[doc = "Bit 4 - Allows auto flow control."]
    #[inline(always)]
    #[must_use]
    pub fn afce_mode(&mut self) -> AfceModeW<CprSpec> {
        AfceModeW::new(self, 4)
    }
    #[doc = "Bit 5 - Programmable Transmitter Hold Register Empty interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn thre_mode(&mut self) -> ThreModeW<CprSpec> {
        ThreModeW::new(self, 5)
    }
    #[doc = "Bit 6 - Sir mode not used in this application."]
    #[inline(always)]
    #[must_use]
    pub fn sir_mode(&mut self) -> SirModeW<CprSpec> {
        SirModeW::new(self, 6)
    }
    #[doc = "Bit 7 - LP Sir Mode not used in this application."]
    #[inline(always)]
    #[must_use]
    pub fn sir_lp_mode(&mut self) -> SirLpModeW<CprSpec> {
        SirLpModeW::new(self, 7)
    }
    #[doc = "Bit 8 - Configures the uart to include fifo status register, shadow registers and encoded parameter register."]
    #[inline(always)]
    #[must_use]
    pub fn additional_feat(&mut self) -> AdditionalFeatW<CprSpec> {
        AdditionalFeatW::new(self, 8)
    }
    #[doc = "Bit 9 - Configures the peripheral to have a programmable FIFO access mode. This is used for test purposes, to allow the receiver FIFO to be written and the transmit FIFO to be read when FIFOs are implemented and enabled."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_access(&mut self) -> FifoAccessW<CprSpec> {
        FifoAccessW::new(self, 9)
    }
    #[doc = "Bit 10 - Configures the peripheral to have three additional FIFO status registers."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_stat(&mut self) -> FifoStatW<CprSpec> {
        FifoStatW::new(self, 10)
    }
    #[doc = "Bit 11 - Configures the peripheral to have seven additional registers that shadow some of the existing register bits that are regularly modified by software. These can be used to reduce the software overhead that is introduced by having to perform read-modify writes."]
    #[inline(always)]
    #[must_use]
    pub fn shadow(&mut self) -> ShadowW<CprSpec> {
        ShadowW::new(self, 11)
    }
    #[doc = "Bit 12 - Configures the peripheral to have a configuration identification register."]
    #[inline(always)]
    #[must_use]
    pub fn uart_add_encoded_param(&mut self) -> UartAddEncodedParamW<CprSpec> {
        UartAddEncodedParamW::new(self, 12)
    }
    #[doc = "Bit 13 - Configures the peripheral to have four additional DMA signals on the interface."]
    #[inline(always)]
    #[must_use]
    pub fn dma_extra(&mut self) -> DmaExtraW<CprSpec> {
        DmaExtraW::new(self, 13)
    }
    #[doc = "Bits 16:23 - Receiver and Transmitter FIFO depth in bytes."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_mode(&mut self) -> FifoModeW<CprSpec> {
        FifoModeW::new(self, 16)
    }
}
#[doc = "Describes various fixed hardware setups states.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cpr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CprSpec;
impl crate::RegisterSpec for CprSpec {
    type Ux = u32;
    const OFFSET: u64 = 244u64;
}
#[doc = "`read()` method returns [`cpr::R`](R) reader structure"]
impl crate::Readable for CprSpec {}
#[doc = "`reset()` method sets cpr to value 0x0037_3f32"]
impl crate::Resettable for CprSpec {
    const RESET_VALUE: u32 = 0x0037_3f32;
}
