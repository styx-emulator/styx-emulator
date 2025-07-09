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
#[doc = "Register `ic_comp_param_1` reader"]
pub type R = crate::R<IcCompParam1Spec>;
#[doc = "Register `ic_comp_param_1` writer"]
pub type W = crate::W<IcCompParam1Spec>;
#[doc = "Sets the APB Data Width.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ApbDataWidth {
    #[doc = "2: `10`"]
    Width32bits = 2,
}
impl From<ApbDataWidth> for u8 {
    #[inline(always)]
    fn from(variant: ApbDataWidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for ApbDataWidth {
    type Ux = u8;
}
#[doc = "Field `apb_data_width` reader - Sets the APB Data Width."]
pub type ApbDataWidthR = crate::FieldReader<ApbDataWidth>;
impl ApbDataWidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<ApbDataWidth> {
        match self.bits {
            2 => Some(ApbDataWidth::Width32bits),
            _ => None,
        }
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_width32bits(&self) -> bool {
        *self == ApbDataWidth::Width32bits
    }
}
#[doc = "Field `apb_data_width` writer - Sets the APB Data Width."]
pub type ApbDataWidthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "The value of this field determines the maximum i2c bus interface speed.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MaxSpeedMode {
    #[doc = "2: `10`"]
    Fast = 2,
}
impl From<MaxSpeedMode> for u8 {
    #[inline(always)]
    fn from(variant: MaxSpeedMode) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for MaxSpeedMode {
    type Ux = u8;
}
#[doc = "Field `max_speed_mode` reader - The value of this field determines the maximum i2c bus interface speed."]
pub type MaxSpeedModeR = crate::FieldReader<MaxSpeedMode>;
impl MaxSpeedModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<MaxSpeedMode> {
        match self.bits {
            2 => Some(MaxSpeedMode::Fast),
            _ => None,
        }
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_fast(&self) -> bool {
        *self == MaxSpeedMode::Fast
    }
}
#[doc = "Field `max_speed_mode` writer - The value of this field determines the maximum i2c bus interface speed."]
pub type MaxSpeedModeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "This makes the *CNT registers readable and writable.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HcCountValues {
    #[doc = "0: `0`"]
    Readwrite = 0,
}
impl From<HcCountValues> for bool {
    #[inline(always)]
    fn from(variant: HcCountValues) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hc_count_values` reader - This makes the *CNT registers readable and writable."]
pub type HcCountValuesR = crate::BitReader<HcCountValues>;
impl HcCountValuesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<HcCountValues> {
        match self.bits {
            false => Some(HcCountValues::Readwrite),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_readwrite(&self) -> bool {
        *self == HcCountValues::Readwrite
    }
}
#[doc = "Field `hc_count_values` writer - This makes the *CNT registers readable and writable."]
pub type HcCountValuesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "All interrupt sources are combined in to a single output.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntrIo {
    #[doc = "1: `1`"]
    Combined = 1,
}
impl From<IntrIo> for bool {
    #[inline(always)]
    fn from(variant: IntrIo) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `intr_io` reader - All interrupt sources are combined in to a single output."]
pub type IntrIoR = crate::BitReader<IntrIo>;
impl IntrIoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<IntrIo> {
        match self.bits {
            true => Some(IntrIo::Combined),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_combined(&self) -> bool {
        *self == IntrIo::Combined
    }
}
#[doc = "Field `intr_io` writer - All interrupt sources are combined in to a single output."]
pub type IntrIoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This configures the inclusion of DMA handshaking interface signals.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HasDma {
    #[doc = "1: `1`"]
    Present = 1,
}
impl From<HasDma> for bool {
    #[inline(always)]
    fn from(variant: HasDma) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `has_dma` reader - This configures the inclusion of DMA handshaking interface signals."]
pub type HasDmaR = crate::BitReader<HasDma>;
impl HasDmaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<HasDma> {
        match self.bits {
            true => Some(HasDma::Present),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_present(&self) -> bool {
        *self == HasDma::Present
    }
}
#[doc = "Field `has_dma` writer - This configures the inclusion of DMA handshaking interface signals."]
pub type HasDmaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "By adding in the encoded parameters, this gives firmware an easy and quick way of identifying the DesignWare component within an I/O memory map. Some critical design-time options determine how a driver should interact with the peripheral. There is a minimal area overhead by including these parameters. Allows a single driver to be developed for each component which will be self-configurable.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddEncodedParams {
    #[doc = "1: `1`"]
    Addencparams = 1,
}
impl From<AddEncodedParams> for bool {
    #[inline(always)]
    fn from(variant: AddEncodedParams) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `add_encoded_params` reader - By adding in the encoded parameters, this gives firmware an easy and quick way of identifying the DesignWare component within an I/O memory map. Some critical design-time options determine how a driver should interact with the peripheral. There is a minimal area overhead by including these parameters. Allows a single driver to be developed for each component which will be self-configurable."]
pub type AddEncodedParamsR = crate::BitReader<AddEncodedParams>;
impl AddEncodedParamsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<AddEncodedParams> {
        match self.bits {
            true => Some(AddEncodedParams::Addencparams),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_addencparams(&self) -> bool {
        *self == AddEncodedParams::Addencparams
    }
}
#[doc = "Field `add_encoded_params` writer - By adding in the encoded parameters, this gives firmware an easy and quick way of identifying the DesignWare component within an I/O memory map. Some critical design-time options determine how a driver should interact with the peripheral. There is a minimal area overhead by including these parameters. Allows a single driver to be developed for each component which will be self-configurable."]
pub type AddEncodedParamsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Sets Rx FIFO Depth.\n\nValue on reset: 63"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RxBufferDepth {
    #[doc = "64: `1000000`"]
    Fifo64bytes = 64,
}
impl From<RxBufferDepth> for u8 {
    #[inline(always)]
    fn from(variant: RxBufferDepth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for RxBufferDepth {
    type Ux = u8;
}
#[doc = "Field `rx_buffer_depth` reader - Sets Rx FIFO Depth."]
pub type RxBufferDepthR = crate::FieldReader<RxBufferDepth>;
impl RxBufferDepthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<RxBufferDepth> {
        match self.bits {
            64 => Some(RxBufferDepth::Fifo64bytes),
            _ => None,
        }
    }
    #[doc = "`1000000`"]
    #[inline(always)]
    pub fn is_fifo64bytes(&self) -> bool {
        *self == RxBufferDepth::Fifo64bytes
    }
}
#[doc = "Field `rx_buffer_depth` writer - Sets Rx FIFO Depth."]
pub type RxBufferDepthW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Sets Tx FIFO Depth.\n\nValue on reset: 63"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TxBufferDepth {
    #[doc = "64: `1000000`"]
    Fifo64bytes = 64,
}
impl From<TxBufferDepth> for u8 {
    #[inline(always)]
    fn from(variant: TxBufferDepth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for TxBufferDepth {
    type Ux = u8;
}
#[doc = "Field `tx_buffer_depth` reader - Sets Tx FIFO Depth."]
pub type TxBufferDepthR = crate::FieldReader<TxBufferDepth>;
impl TxBufferDepthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<TxBufferDepth> {
        match self.bits {
            64 => Some(TxBufferDepth::Fifo64bytes),
            _ => None,
        }
    }
    #[doc = "`1000000`"]
    #[inline(always)]
    pub fn is_fifo64bytes(&self) -> bool {
        *self == TxBufferDepth::Fifo64bytes
    }
}
#[doc = "Field `tx_buffer_depth` writer - Sets Tx FIFO Depth."]
pub type TxBufferDepthW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:1 - Sets the APB Data Width."]
    #[inline(always)]
    pub fn apb_data_width(&self) -> ApbDataWidthR {
        ApbDataWidthR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - The value of this field determines the maximum i2c bus interface speed."]
    #[inline(always)]
    pub fn max_speed_mode(&self) -> MaxSpeedModeR {
        MaxSpeedModeR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bit 4 - This makes the *CNT registers readable and writable."]
    #[inline(always)]
    pub fn hc_count_values(&self) -> HcCountValuesR {
        HcCountValuesR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - All interrupt sources are combined in to a single output."]
    #[inline(always)]
    pub fn intr_io(&self) -> IntrIoR {
        IntrIoR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This configures the inclusion of DMA handshaking interface signals."]
    #[inline(always)]
    pub fn has_dma(&self) -> HasDmaR {
        HasDmaR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - By adding in the encoded parameters, this gives firmware an easy and quick way of identifying the DesignWare component within an I/O memory map. Some critical design-time options determine how a driver should interact with the peripheral. There is a minimal area overhead by including these parameters. Allows a single driver to be developed for each component which will be self-configurable."]
    #[inline(always)]
    pub fn add_encoded_params(&self) -> AddEncodedParamsR {
        AddEncodedParamsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:15 - Sets Rx FIFO Depth."]
    #[inline(always)]
    pub fn rx_buffer_depth(&self) -> RxBufferDepthR {
        RxBufferDepthR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Sets Tx FIFO Depth."]
    #[inline(always)]
    pub fn tx_buffer_depth(&self) -> TxBufferDepthR {
        TxBufferDepthR::new(((self.bits >> 16) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Sets the APB Data Width."]
    #[inline(always)]
    #[must_use]
    pub fn apb_data_width(&mut self) -> ApbDataWidthW<IcCompParam1Spec> {
        ApbDataWidthW::new(self, 0)
    }
    #[doc = "Bits 2:3 - The value of this field determines the maximum i2c bus interface speed."]
    #[inline(always)]
    #[must_use]
    pub fn max_speed_mode(&mut self) -> MaxSpeedModeW<IcCompParam1Spec> {
        MaxSpeedModeW::new(self, 2)
    }
    #[doc = "Bit 4 - This makes the *CNT registers readable and writable."]
    #[inline(always)]
    #[must_use]
    pub fn hc_count_values(&mut self) -> HcCountValuesW<IcCompParam1Spec> {
        HcCountValuesW::new(self, 4)
    }
    #[doc = "Bit 5 - All interrupt sources are combined in to a single output."]
    #[inline(always)]
    #[must_use]
    pub fn intr_io(&mut self) -> IntrIoW<IcCompParam1Spec> {
        IntrIoW::new(self, 5)
    }
    #[doc = "Bit 6 - This configures the inclusion of DMA handshaking interface signals."]
    #[inline(always)]
    #[must_use]
    pub fn has_dma(&mut self) -> HasDmaW<IcCompParam1Spec> {
        HasDmaW::new(self, 6)
    }
    #[doc = "Bit 7 - By adding in the encoded parameters, this gives firmware an easy and quick way of identifying the DesignWare component within an I/O memory map. Some critical design-time options determine how a driver should interact with the peripheral. There is a minimal area overhead by including these parameters. Allows a single driver to be developed for each component which will be self-configurable."]
    #[inline(always)]
    #[must_use]
    pub fn add_encoded_params(&mut self) -> AddEncodedParamsW<IcCompParam1Spec> {
        AddEncodedParamsW::new(self, 7)
    }
    #[doc = "Bits 8:15 - Sets Rx FIFO Depth."]
    #[inline(always)]
    #[must_use]
    pub fn rx_buffer_depth(&mut self) -> RxBufferDepthW<IcCompParam1Spec> {
        RxBufferDepthW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Sets Tx FIFO Depth."]
    #[inline(always)]
    #[must_use]
    pub fn tx_buffer_depth(&mut self) -> TxBufferDepthW<IcCompParam1Spec> {
        TxBufferDepthW::new(self, 16)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_comp_param_1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcCompParam1Spec;
impl crate::RegisterSpec for IcCompParam1Spec {
    type Ux = u32;
    const OFFSET: u64 = 244u64;
}
#[doc = "`read()` method returns [`ic_comp_param_1::R`](R) reader structure"]
impl crate::Readable for IcCompParam1Spec {}
#[doc = "`reset()` method sets ic_comp_param_1 to value 0x003f_3fea"]
impl crate::Resettable for IcCompParam1Spec {
    const RESET_VALUE: u32 = 0x003f_3fea;
}
