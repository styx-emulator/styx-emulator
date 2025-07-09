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
#[doc = "Register `mon_gpio_config_reg1` reader"]
pub type R = crate::R<MonGpioConfigReg1Spec>;
#[doc = "Register `mon_gpio_config_reg1` writer"]
pub type W = crate::W<MonGpioConfigReg1Spec>;
#[doc = "Fixed to support an APB data bus width of 32-bits.\n\nValue on reset: 2"]
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
#[doc = "Field `apb_data_width` reader - Fixed to support an APB data bus width of 32-bits."]
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
#[doc = "Field `apb_data_width` writer - Fixed to support an APB data bus width of 32-bits."]
pub type ApbDataWidthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "The value of this register is fixed at one port (Port A).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NumPorts {
    #[doc = "0: `0`"]
    Oneporta = 0,
}
impl From<NumPorts> for u8 {
    #[inline(always)]
    fn from(variant: NumPorts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for NumPorts {
    type Ux = u8;
}
#[doc = "Field `num_ports` reader - The value of this register is fixed at one port (Port A)."]
pub type NumPortsR = crate::FieldReader<NumPorts>;
impl NumPortsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<NumPorts> {
        match self.bits {
            0 => Some(NumPorts::Oneporta),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_oneporta(&self) -> bool {
        *self == NumPorts::Oneporta
    }
}
#[doc = "Field `num_ports` writer - The value of this register is fixed at one port (Port A)."]
pub type NumPortsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Indicates the mode of operation of Port A to be software controlled only.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortaSingleCtl {
    #[doc = "1: `1`"]
    Softctlonly = 1,
}
impl From<PortaSingleCtl> for bool {
    #[inline(always)]
    fn from(variant: PortaSingleCtl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `porta_single_ctl` reader - Indicates the mode of operation of Port A to be software controlled only."]
pub type PortaSingleCtlR = crate::BitReader<PortaSingleCtl>;
impl PortaSingleCtlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<PortaSingleCtl> {
        match self.bits {
            true => Some(PortaSingleCtl::Softctlonly),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_softctlonly(&self) -> bool {
        *self == PortaSingleCtl::Softctlonly
    }
}
#[doc = "Field `porta_single_ctl` writer - Indicates the mode of operation of Port A to be software controlled only."]
pub type PortaSingleCtlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates the mode of operation of Port B to be software controlled only. Ignored because there is no Port B in the GPIO.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortbSingleCtl {
    #[doc = "1: `1`"]
    Softctlonly = 1,
}
impl From<PortbSingleCtl> for bool {
    #[inline(always)]
    fn from(variant: PortbSingleCtl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `portb_single_ctl` reader - Indicates the mode of operation of Port B to be software controlled only. Ignored because there is no Port B in the GPIO."]
pub type PortbSingleCtlR = crate::BitReader<PortbSingleCtl>;
impl PortbSingleCtlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<PortbSingleCtl> {
        match self.bits {
            true => Some(PortbSingleCtl::Softctlonly),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_softctlonly(&self) -> bool {
        *self == PortbSingleCtl::Softctlonly
    }
}
#[doc = "Field `portb_single_ctl` writer - Indicates the mode of operation of Port B to be software controlled only. Ignored because there is no Port B in the GPIO."]
pub type PortbSingleCtlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates the mode of operation of Port C to be software controlled only. Ignored because there is no Port C in the GPIO.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortcSingleCtl {
    #[doc = "1: `1`"]
    Softctlonly = 1,
}
impl From<PortcSingleCtl> for bool {
    #[inline(always)]
    fn from(variant: PortcSingleCtl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `portc_single_ctl` reader - Indicates the mode of operation of Port C to be software controlled only. Ignored because there is no Port C in the GPIO."]
pub type PortcSingleCtlR = crate::BitReader<PortcSingleCtl>;
impl PortcSingleCtlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<PortcSingleCtl> {
        match self.bits {
            true => Some(PortcSingleCtl::Softctlonly),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_softctlonly(&self) -> bool {
        *self == PortcSingleCtl::Softctlonly
    }
}
#[doc = "Field `portc_single_ctl` writer - Indicates the mode of operation of Port C to be software controlled only. Ignored because there is no Port C in the GPIO."]
pub type PortcSingleCtlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates the mode of operation of Port D to be software controlled only. Ignored because there is no Port D in the GPIO.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortdSingleCtl {
    #[doc = "1: `1`"]
    Softctlonly = 1,
}
impl From<PortdSingleCtl> for bool {
    #[inline(always)]
    fn from(variant: PortdSingleCtl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `portd_single_ctl` reader - Indicates the mode of operation of Port D to be software controlled only. Ignored because there is no Port D in the GPIO."]
pub type PortdSingleCtlR = crate::BitReader<PortdSingleCtl>;
impl PortdSingleCtlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<PortdSingleCtl> {
        match self.bits {
            true => Some(PortdSingleCtl::Softctlonly),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_softctlonly(&self) -> bool {
        *self == PortdSingleCtl::Softctlonly
    }
}
#[doc = "Field `portd_single_ctl` writer - Indicates the mode of operation of Port D to be software controlled only. Ignored because there is no Port D in the GPIO."]
pub type PortdSingleCtlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The value is fixed to enable Port A configuration to be controlled by software only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwPorta {
    #[doc = "0: `0`"]
    Portanohard = 0,
}
impl From<HwPorta> for bool {
    #[inline(always)]
    fn from(variant: HwPorta) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hw_porta` reader - The value is fixed to enable Port A configuration to be controlled by software only."]
pub type HwPortaR = crate::BitReader<HwPorta>;
impl HwPortaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<HwPorta> {
        match self.bits {
            false => Some(HwPorta::Portanohard),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_portanohard(&self) -> bool {
        *self == HwPorta::Portanohard
    }
}
#[doc = "Field `hw_porta` writer - The value is fixed to enable Port A configuration to be controlled by software only."]
pub type HwPortaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The value of this field is fixed to allow interrupts on Port A.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortaIntr {
    #[doc = "1: `1`"]
    Portainterr = 1,
}
impl From<PortaIntr> for bool {
    #[inline(always)]
    fn from(variant: PortaIntr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `porta_intr` reader - The value of this field is fixed to allow interrupts on Port A."]
pub type PortaIntrR = crate::BitReader<PortaIntr>;
impl PortaIntrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<PortaIntr> {
        match self.bits {
            true => Some(PortaIntr::Portainterr),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_portainterr(&self) -> bool {
        *self == PortaIntr::Portainterr
    }
}
#[doc = "Field `porta_intr` writer - The value of this field is fixed to allow interrupts on Port A."]
pub type PortaIntrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The value of this field is fixed to not allow debouncing of the Port A signals.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Debounce {
    #[doc = "0: `0`"]
    DebounceaDisabled = 0,
}
impl From<Debounce> for bool {
    #[inline(always)]
    fn from(variant: Debounce) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `debounce` reader - The value of this field is fixed to not allow debouncing of the Port A signals."]
pub type DebounceR = crate::BitReader<Debounce>;
impl DebounceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Debounce> {
        match self.bits {
            false => Some(Debounce::DebounceaDisabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_debouncea_disabled(&self) -> bool {
        *self == Debounce::DebounceaDisabled
    }
}
#[doc = "Field `debounce` writer - The value of this field is fixed to not allow debouncing of the Port A signals."]
pub type DebounceW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Fixed to allow the indentification of the Designware IP component.\n\nValue on reset: 1"]
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
#[doc = "Field `add_encoded_params` reader - Fixed to allow the indentification of the Designware IP component."]
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
#[doc = "Field `add_encoded_params` writer - Fixed to allow the indentification of the Designware IP component."]
pub type AddEncodedParamsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Provides an ID code value\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpioId {
    #[doc = "0: `0`"]
    IdcodeExcluded = 0,
}
impl From<GpioId> for bool {
    #[inline(always)]
    fn from(variant: GpioId) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gpio_id` reader - Provides an ID code value"]
pub type GpioIdR = crate::BitReader<GpioId>;
impl GpioIdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioId> {
        match self.bits {
            false => Some(GpioId::IdcodeExcluded),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idcode_excluded(&self) -> bool {
        *self == GpioId::IdcodeExcluded
    }
}
#[doc = "Field `gpio_id` writer - Provides an ID code value"]
pub type GpioIdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This value is fixed at 32 bits.\n\nValue on reset: 31"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncodedIdWidth {
    #[doc = "31: `11111`"]
    Encidwidth = 31,
}
impl From<EncodedIdWidth> for u8 {
    #[inline(always)]
    fn from(variant: EncodedIdWidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for EncodedIdWidth {
    type Ux = u8;
}
#[doc = "Field `encoded_id_width` reader - This value is fixed at 32 bits."]
pub type EncodedIdWidthR = crate::FieldReader<EncodedIdWidth>;
impl EncodedIdWidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<EncodedIdWidth> {
        match self.bits {
            31 => Some(EncodedIdWidth::Encidwidth),
            _ => None,
        }
    }
    #[doc = "`11111`"]
    #[inline(always)]
    pub fn is_encidwidth(&self) -> bool {
        *self == EncodedIdWidth::Encidwidth
    }
}
#[doc = "Field `encoded_id_width` writer - This value is fixed at 32 bits."]
pub type EncodedIdWidthW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:1 - Fixed to support an APB data bus width of 32-bits."]
    #[inline(always)]
    pub fn apb_data_width(&self) -> ApbDataWidthR {
        ApbDataWidthR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - The value of this register is fixed at one port (Port A)."]
    #[inline(always)]
    pub fn num_ports(&self) -> NumPortsR {
        NumPortsR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bit 4 - Indicates the mode of operation of Port A to be software controlled only."]
    #[inline(always)]
    pub fn porta_single_ctl(&self) -> PortaSingleCtlR {
        PortaSingleCtlR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Indicates the mode of operation of Port B to be software controlled only. Ignored because there is no Port B in the GPIO."]
    #[inline(always)]
    pub fn portb_single_ctl(&self) -> PortbSingleCtlR {
        PortbSingleCtlR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Indicates the mode of operation of Port C to be software controlled only. Ignored because there is no Port C in the GPIO."]
    #[inline(always)]
    pub fn portc_single_ctl(&self) -> PortcSingleCtlR {
        PortcSingleCtlR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Indicates the mode of operation of Port D to be software controlled only. Ignored because there is no Port D in the GPIO."]
    #[inline(always)]
    pub fn portd_single_ctl(&self) -> PortdSingleCtlR {
        PortdSingleCtlR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - The value is fixed to enable Port A configuration to be controlled by software only."]
    #[inline(always)]
    pub fn hw_porta(&self) -> HwPortaR {
        HwPortaR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 12 - The value of this field is fixed to allow interrupts on Port A."]
    #[inline(always)]
    pub fn porta_intr(&self) -> PortaIntrR {
        PortaIntrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - The value of this field is fixed to not allow debouncing of the Port A signals."]
    #[inline(always)]
    pub fn debounce(&self) -> DebounceR {
        DebounceR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Fixed to allow the indentification of the Designware IP component."]
    #[inline(always)]
    pub fn add_encoded_params(&self) -> AddEncodedParamsR {
        AddEncodedParamsR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Provides an ID code value"]
    #[inline(always)]
    pub fn gpio_id(&self) -> GpioIdR {
        GpioIdR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:20 - This value is fixed at 32 bits."]
    #[inline(always)]
    pub fn encoded_id_width(&self) -> EncodedIdWidthR {
        EncodedIdWidthR::new(((self.bits >> 16) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Fixed to support an APB data bus width of 32-bits."]
    #[inline(always)]
    #[must_use]
    pub fn apb_data_width(&mut self) -> ApbDataWidthW<MonGpioConfigReg1Spec> {
        ApbDataWidthW::new(self, 0)
    }
    #[doc = "Bits 2:3 - The value of this register is fixed at one port (Port A)."]
    #[inline(always)]
    #[must_use]
    pub fn num_ports(&mut self) -> NumPortsW<MonGpioConfigReg1Spec> {
        NumPortsW::new(self, 2)
    }
    #[doc = "Bit 4 - Indicates the mode of operation of Port A to be software controlled only."]
    #[inline(always)]
    #[must_use]
    pub fn porta_single_ctl(&mut self) -> PortaSingleCtlW<MonGpioConfigReg1Spec> {
        PortaSingleCtlW::new(self, 4)
    }
    #[doc = "Bit 5 - Indicates the mode of operation of Port B to be software controlled only. Ignored because there is no Port B in the GPIO."]
    #[inline(always)]
    #[must_use]
    pub fn portb_single_ctl(&mut self) -> PortbSingleCtlW<MonGpioConfigReg1Spec> {
        PortbSingleCtlW::new(self, 5)
    }
    #[doc = "Bit 6 - Indicates the mode of operation of Port C to be software controlled only. Ignored because there is no Port C in the GPIO."]
    #[inline(always)]
    #[must_use]
    pub fn portc_single_ctl(&mut self) -> PortcSingleCtlW<MonGpioConfigReg1Spec> {
        PortcSingleCtlW::new(self, 6)
    }
    #[doc = "Bit 7 - Indicates the mode of operation of Port D to be software controlled only. Ignored because there is no Port D in the GPIO."]
    #[inline(always)]
    #[must_use]
    pub fn portd_single_ctl(&mut self) -> PortdSingleCtlW<MonGpioConfigReg1Spec> {
        PortdSingleCtlW::new(self, 7)
    }
    #[doc = "Bit 8 - The value is fixed to enable Port A configuration to be controlled by software only."]
    #[inline(always)]
    #[must_use]
    pub fn hw_porta(&mut self) -> HwPortaW<MonGpioConfigReg1Spec> {
        HwPortaW::new(self, 8)
    }
    #[doc = "Bit 12 - The value of this field is fixed to allow interrupts on Port A."]
    #[inline(always)]
    #[must_use]
    pub fn porta_intr(&mut self) -> PortaIntrW<MonGpioConfigReg1Spec> {
        PortaIntrW::new(self, 12)
    }
    #[doc = "Bit 13 - The value of this field is fixed to not allow debouncing of the Port A signals."]
    #[inline(always)]
    #[must_use]
    pub fn debounce(&mut self) -> DebounceW<MonGpioConfigReg1Spec> {
        DebounceW::new(self, 13)
    }
    #[doc = "Bit 14 - Fixed to allow the indentification of the Designware IP component."]
    #[inline(always)]
    #[must_use]
    pub fn add_encoded_params(&mut self) -> AddEncodedParamsW<MonGpioConfigReg1Spec> {
        AddEncodedParamsW::new(self, 14)
    }
    #[doc = "Bit 15 - Provides an ID code value"]
    #[inline(always)]
    #[must_use]
    pub fn gpio_id(&mut self) -> GpioIdW<MonGpioConfigReg1Spec> {
        GpioIdW::new(self, 15)
    }
    #[doc = "Bits 16:20 - This value is fixed at 32 bits."]
    #[inline(always)]
    #[must_use]
    pub fn encoded_id_width(&mut self) -> EncodedIdWidthW<MonGpioConfigReg1Spec> {
        EncodedIdWidthW::new(self, 16)
    }
}
#[doc = "Reports settings of various GPIO configuration parameters\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_config_reg1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioConfigReg1Spec;
impl crate::RegisterSpec for MonGpioConfigReg1Spec {
    type Ux = u32;
    const OFFSET: u64 = 2164u64;
}
#[doc = "`read()` method returns [`mon_gpio_config_reg1::R`](R) reader structure"]
impl crate::Readable for MonGpioConfigReg1Spec {}
#[doc = "`reset()` method sets mon_gpio_config_reg1 to value 0x001f_50f2"]
impl crate::Resettable for MonGpioConfigReg1Spec {
    const RESET_VALUE: u32 = 0x001f_50f2;
}
