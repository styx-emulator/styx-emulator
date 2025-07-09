// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_config_reg2` reader"]
pub type R = crate::R<GpioConfigReg2Spec>;
#[doc = "Register `gpio_config_reg2` writer"]
pub type W = crate::W<GpioConfigReg2Spec>;
#[doc = "Specifies the width of GPIO Port A. The value 28 represents the 29-bit width less one.\n\nValue on reset: 28"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncodedIdPwidthA {
    #[doc = "7: `111`"]
    Widthlessone8bits = 7,
    #[doc = "28: `11100`"]
    Widthlessone29bits = 28,
}
impl From<EncodedIdPwidthA> for u8 {
    #[inline(always)]
    fn from(variant: EncodedIdPwidthA) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for EncodedIdPwidthA {
    type Ux = u8;
}
#[doc = "Field `encoded_id_pwidth_a` reader - Specifies the width of GPIO Port A. The value 28 represents the 29-bit width less one."]
pub type EncodedIdPwidthAR = crate::FieldReader<EncodedIdPwidthA>;
impl EncodedIdPwidthAR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<EncodedIdPwidthA> {
        match self.bits {
            7 => Some(EncodedIdPwidthA::Widthlessone8bits),
            28 => Some(EncodedIdPwidthA::Widthlessone29bits),
            _ => None,
        }
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_widthlessone8bits(&self) -> bool {
        *self == EncodedIdPwidthA::Widthlessone8bits
    }
    #[doc = "`11100`"]
    #[inline(always)]
    pub fn is_widthlessone29bits(&self) -> bool {
        *self == EncodedIdPwidthA::Widthlessone29bits
    }
}
#[doc = "Field `encoded_id_pwidth_a` writer - Specifies the width of GPIO Port A. The value 28 represents the 29-bit width less one."]
pub type EncodedIdPwidthAW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Specifies the width of GPIO Port B. Ignored because there is no Port B in the GPIO.\n\nValue on reset: 7"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncodedIdPwidthB {
    #[doc = "7: `111`"]
    Widthlessone8bits = 7,
    #[doc = "28: `11100`"]
    Widthlessone29bits = 28,
}
impl From<EncodedIdPwidthB> for u8 {
    #[inline(always)]
    fn from(variant: EncodedIdPwidthB) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for EncodedIdPwidthB {
    type Ux = u8;
}
#[doc = "Field `encoded_id_pwidth_b` reader - Specifies the width of GPIO Port B. Ignored because there is no Port B in the GPIO."]
pub type EncodedIdPwidthBR = crate::FieldReader<EncodedIdPwidthB>;
impl EncodedIdPwidthBR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<EncodedIdPwidthB> {
        match self.bits {
            7 => Some(EncodedIdPwidthB::Widthlessone8bits),
            28 => Some(EncodedIdPwidthB::Widthlessone29bits),
            _ => None,
        }
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_widthlessone8bits(&self) -> bool {
        *self == EncodedIdPwidthB::Widthlessone8bits
    }
    #[doc = "`11100`"]
    #[inline(always)]
    pub fn is_widthlessone29bits(&self) -> bool {
        *self == EncodedIdPwidthB::Widthlessone29bits
    }
}
#[doc = "Field `encoded_id_pwidth_b` writer - Specifies the width of GPIO Port B. Ignored because there is no Port B in the GPIO."]
pub type EncodedIdPwidthBW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Specifies the width of GPIO Port C. Ignored because there is no Port C in the GPIO.\n\nValue on reset: 7"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncodedIdPwidthC {
    #[doc = "7: `111`"]
    Widthlessone8bits = 7,
    #[doc = "28: `11100`"]
    Widthlessone29bits = 28,
}
impl From<EncodedIdPwidthC> for u8 {
    #[inline(always)]
    fn from(variant: EncodedIdPwidthC) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for EncodedIdPwidthC {
    type Ux = u8;
}
#[doc = "Field `encoded_id_pwidth_c` reader - Specifies the width of GPIO Port C. Ignored because there is no Port C in the GPIO."]
pub type EncodedIdPwidthCR = crate::FieldReader<EncodedIdPwidthC>;
impl EncodedIdPwidthCR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<EncodedIdPwidthC> {
        match self.bits {
            7 => Some(EncodedIdPwidthC::Widthlessone8bits),
            28 => Some(EncodedIdPwidthC::Widthlessone29bits),
            _ => None,
        }
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_widthlessone8bits(&self) -> bool {
        *self == EncodedIdPwidthC::Widthlessone8bits
    }
    #[doc = "`11100`"]
    #[inline(always)]
    pub fn is_widthlessone29bits(&self) -> bool {
        *self == EncodedIdPwidthC::Widthlessone29bits
    }
}
#[doc = "Field `encoded_id_pwidth_c` writer - Specifies the width of GPIO Port C. Ignored because there is no Port C in the GPIO."]
pub type EncodedIdPwidthCW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Specifies the width of GPIO Port D. Ignored because there is no Port D in the GPIO.\n\nValue on reset: 7"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncodedIdPwidthD {
    #[doc = "7: `111`"]
    Widthlessone8bits = 7,
    #[doc = "28: `11100`"]
    Widthlessone29bits = 28,
}
impl From<EncodedIdPwidthD> for u8 {
    #[inline(always)]
    fn from(variant: EncodedIdPwidthD) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for EncodedIdPwidthD {
    type Ux = u8;
}
#[doc = "Field `encoded_id_pwidth_d` reader - Specifies the width of GPIO Port D. Ignored because there is no Port D in the GPIO."]
pub type EncodedIdPwidthDR = crate::FieldReader<EncodedIdPwidthD>;
impl EncodedIdPwidthDR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<EncodedIdPwidthD> {
        match self.bits {
            7 => Some(EncodedIdPwidthD::Widthlessone8bits),
            28 => Some(EncodedIdPwidthD::Widthlessone29bits),
            _ => None,
        }
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_widthlessone8bits(&self) -> bool {
        *self == EncodedIdPwidthD::Widthlessone8bits
    }
    #[doc = "`11100`"]
    #[inline(always)]
    pub fn is_widthlessone29bits(&self) -> bool {
        *self == EncodedIdPwidthD::Widthlessone29bits
    }
}
#[doc = "Field `encoded_id_pwidth_d` writer - Specifies the width of GPIO Port D. Ignored because there is no Port D in the GPIO."]
pub type EncodedIdPwidthDW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - Specifies the width of GPIO Port A. The value 28 represents the 29-bit width less one."]
    #[inline(always)]
    pub fn encoded_id_pwidth_a(&self) -> EncodedIdPwidthAR {
        EncodedIdPwidthAR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 5:9 - Specifies the width of GPIO Port B. Ignored because there is no Port B in the GPIO."]
    #[inline(always)]
    pub fn encoded_id_pwidth_b(&self) -> EncodedIdPwidthBR {
        EncodedIdPwidthBR::new(((self.bits >> 5) & 0x1f) as u8)
    }
    #[doc = "Bits 10:14 - Specifies the width of GPIO Port C. Ignored because there is no Port C in the GPIO."]
    #[inline(always)]
    pub fn encoded_id_pwidth_c(&self) -> EncodedIdPwidthCR {
        EncodedIdPwidthCR::new(((self.bits >> 10) & 0x1f) as u8)
    }
    #[doc = "Bits 15:19 - Specifies the width of GPIO Port D. Ignored because there is no Port D in the GPIO."]
    #[inline(always)]
    pub fn encoded_id_pwidth_d(&self) -> EncodedIdPwidthDR {
        EncodedIdPwidthDR::new(((self.bits >> 15) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - Specifies the width of GPIO Port A. The value 28 represents the 29-bit width less one."]
    #[inline(always)]
    #[must_use]
    pub fn encoded_id_pwidth_a(&mut self) -> EncodedIdPwidthAW<GpioConfigReg2Spec> {
        EncodedIdPwidthAW::new(self, 0)
    }
    #[doc = "Bits 5:9 - Specifies the width of GPIO Port B. Ignored because there is no Port B in the GPIO."]
    #[inline(always)]
    #[must_use]
    pub fn encoded_id_pwidth_b(&mut self) -> EncodedIdPwidthBW<GpioConfigReg2Spec> {
        EncodedIdPwidthBW::new(self, 5)
    }
    #[doc = "Bits 10:14 - Specifies the width of GPIO Port C. Ignored because there is no Port C in the GPIO."]
    #[inline(always)]
    #[must_use]
    pub fn encoded_id_pwidth_c(&mut self) -> EncodedIdPwidthCW<GpioConfigReg2Spec> {
        EncodedIdPwidthCW::new(self, 10)
    }
    #[doc = "Bits 15:19 - Specifies the width of GPIO Port D. Ignored because there is no Port D in the GPIO."]
    #[inline(always)]
    #[must_use]
    pub fn encoded_id_pwidth_d(&mut self) -> EncodedIdPwidthDW<GpioConfigReg2Spec> {
        EncodedIdPwidthDW::new(self, 15)
    }
}
#[doc = "Specifies the bit width of port A.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_config_reg2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioConfigReg2Spec;
impl crate::RegisterSpec for GpioConfigReg2Spec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`gpio_config_reg2::R`](R) reader structure"]
impl crate::Readable for GpioConfigReg2Spec {}
#[doc = "`reset()` method sets gpio_config_reg2 to value 0x0003_9cfc"]
impl crate::Resettable for GpioConfigReg2Spec {
    const RESET_VALUE: u32 = 0x0003_9cfc;
}
