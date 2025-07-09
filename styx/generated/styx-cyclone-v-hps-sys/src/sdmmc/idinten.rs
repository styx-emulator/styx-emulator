// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idinten` reader"]
pub type R = crate::R<IdintenSpec>;
#[doc = "Register `idinten` writer"]
pub type W = crate::W<IdintenSpec>;
#[doc = "Enables and Disables Transmit Interrupt when Normal Interrupt Summary Enable is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ti {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Ti> for bool {
    #[inline(always)]
    fn from(variant: Ti) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ti` reader - Enables and Disables Transmit Interrupt when Normal Interrupt Summary Enable is set."]
pub type TiR = crate::BitReader<Ti>;
impl TiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ti {
        match self.bits {
            true => Ti::Enabled,
            false => Ti::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ti::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ti::Disabled
    }
}
#[doc = "Field `ti` writer - Enables and Disables Transmit Interrupt when Normal Interrupt Summary Enable is set."]
pub type TiW<'a, REG> = crate::BitWriter<'a, REG, Ti>;
impl<'a, REG> TiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ti::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ti::Disabled)
    }
}
#[doc = "Enables and Disables Receive Interrupt when Normal Interrupt Summary Enable is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ri {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Ri> for bool {
    #[inline(always)]
    fn from(variant: Ri) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ri` reader - Enables and Disables Receive Interrupt when Normal Interrupt Summary Enable is set."]
pub type RiR = crate::BitReader<Ri>;
impl RiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ri {
        match self.bits {
            true => Ri::Enabled,
            false => Ri::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ri::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ri::Disabled
    }
}
#[doc = "Field `ri` writer - Enables and Disables Receive Interrupt when Normal Interrupt Summary Enable is set."]
pub type RiW<'a, REG> = crate::BitWriter<'a, REG, Ri>;
impl<'a, REG> RiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ri::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ri::Disabled)
    }
}
#[doc = "When set with Abnormal Interrupt Summary Enable, the Fatal Bus Error Interrupt is enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fbe {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Fbe> for bool {
    #[inline(always)]
    fn from(variant: Fbe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fbe` reader - When set with Abnormal Interrupt Summary Enable, the Fatal Bus Error Interrupt is enabled."]
pub type FbeR = crate::BitReader<Fbe>;
impl FbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fbe {
        match self.bits {
            true => Fbe::Enabled,
            false => Fbe::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Fbe::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Fbe::Disabled
    }
}
#[doc = "Field `fbe` writer - When set with Abnormal Interrupt Summary Enable, the Fatal Bus Error Interrupt is enabled."]
pub type FbeW<'a, REG> = crate::BitWriter<'a, REG, Fbe>;
impl<'a, REG> FbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fbe::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fbe::Disabled)
    }
}
#[doc = "When set along with Abnormal Interrupt Summary Enable, the DU interrupt is enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Du {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Du> for bool {
    #[inline(always)]
    fn from(variant: Du) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `du` reader - When set along with Abnormal Interrupt Summary Enable, the DU interrupt is enabled."]
pub type DuR = crate::BitReader<Du>;
impl DuR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Du {
        match self.bits {
            true => Du::Enabled,
            false => Du::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Du::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Du::Disabled
    }
}
#[doc = "Field `du` writer - When set along with Abnormal Interrupt Summary Enable, the DU interrupt is enabled."]
pub type DuW<'a, REG> = crate::BitWriter<'a, REG, Du>;
impl<'a, REG> DuW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Du::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Du::Disabled)
    }
}
#[doc = "Enable and disable Card Error Interrupt Summary\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ces {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Ces> for bool {
    #[inline(always)]
    fn from(variant: Ces) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ces` reader - Enable and disable Card Error Interrupt Summary"]
pub type CesR = crate::BitReader<Ces>;
impl CesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ces {
        match self.bits {
            true => Ces::Enabled,
            false => Ces::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ces::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ces::Disabled
    }
}
#[doc = "Field `ces` writer - Enable and disable Card Error Interrupt Summary"]
pub type CesW<'a, REG> = crate::BitWriter<'a, REG, Ces>;
impl<'a, REG> CesW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ces::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ces::Disabled)
    }
}
#[doc = "Enable and Disable Normal Interrupt Summary\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ni {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Ni> for bool {
    #[inline(always)]
    fn from(variant: Ni) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ni` reader - Enable and Disable Normal Interrupt Summary"]
pub type NiR = crate::BitReader<Ni>;
impl NiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ni {
        match self.bits {
            true => Ni::Enabled,
            false => Ni::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ni::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ni::Disabled
    }
}
#[doc = "Field `ni` writer - Enable and Disable Normal Interrupt Summary"]
pub type NiW<'a, REG> = crate::BitWriter<'a, REG, Ni>;
impl<'a, REG> NiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ni::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ni::Disabled)
    }
}
#[doc = "This bit enables the following bits: IDINTEN\\[2\\]
- Fatal Bus Error Interrupt IDINTEN\\[4\\]
- DU Interrupt IDINTEN\\[5\\]
- Card Error Summary Interrupt\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ai {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Ai> for bool {
    #[inline(always)]
    fn from(variant: Ai) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ai` reader - This bit enables the following bits: IDINTEN\\[2\\]
- Fatal Bus Error Interrupt IDINTEN\\[4\\]
- DU Interrupt IDINTEN\\[5\\]
- Card Error Summary Interrupt"]
pub type AiR = crate::BitReader<Ai>;
impl AiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ai {
        match self.bits {
            true => Ai::Enabled,
            false => Ai::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ai::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ai::Disabled
    }
}
#[doc = "Field `ai` writer - This bit enables the following bits: IDINTEN\\[2\\]
- Fatal Bus Error Interrupt IDINTEN\\[4\\]
- DU Interrupt IDINTEN\\[5\\]
- Card Error Summary Interrupt"]
pub type AiW<'a, REG> = crate::BitWriter<'a, REG, Ai>;
impl<'a, REG> AiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ai::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ai::Disabled)
    }
}
impl R {
    #[doc = "Bit 0 - Enables and Disables Transmit Interrupt when Normal Interrupt Summary Enable is set."]
    #[inline(always)]
    pub fn ti(&self) -> TiR {
        TiR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Enables and Disables Receive Interrupt when Normal Interrupt Summary Enable is set."]
    #[inline(always)]
    pub fn ri(&self) -> RiR {
        RiR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When set with Abnormal Interrupt Summary Enable, the Fatal Bus Error Interrupt is enabled."]
    #[inline(always)]
    pub fn fbe(&self) -> FbeR {
        FbeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - When set along with Abnormal Interrupt Summary Enable, the DU interrupt is enabled."]
    #[inline(always)]
    pub fn du(&self) -> DuR {
        DuR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Enable and disable Card Error Interrupt Summary"]
    #[inline(always)]
    pub fn ces(&self) -> CesR {
        CesR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - Enable and Disable Normal Interrupt Summary"]
    #[inline(always)]
    pub fn ni(&self) -> NiR {
        NiR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit enables the following bits: IDINTEN\\[2\\]
- Fatal Bus Error Interrupt IDINTEN\\[4\\]
- DU Interrupt IDINTEN\\[5\\]
- Card Error Summary Interrupt"]
    #[inline(always)]
    pub fn ai(&self) -> AiR {
        AiR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables and Disables Transmit Interrupt when Normal Interrupt Summary Enable is set."]
    #[inline(always)]
    #[must_use]
    pub fn ti(&mut self) -> TiW<IdintenSpec> {
        TiW::new(self, 0)
    }
    #[doc = "Bit 1 - Enables and Disables Receive Interrupt when Normal Interrupt Summary Enable is set."]
    #[inline(always)]
    #[must_use]
    pub fn ri(&mut self) -> RiW<IdintenSpec> {
        RiW::new(self, 1)
    }
    #[doc = "Bit 2 - When set with Abnormal Interrupt Summary Enable, the Fatal Bus Error Interrupt is enabled."]
    #[inline(always)]
    #[must_use]
    pub fn fbe(&mut self) -> FbeW<IdintenSpec> {
        FbeW::new(self, 2)
    }
    #[doc = "Bit 4 - When set along with Abnormal Interrupt Summary Enable, the DU interrupt is enabled."]
    #[inline(always)]
    #[must_use]
    pub fn du(&mut self) -> DuW<IdintenSpec> {
        DuW::new(self, 4)
    }
    #[doc = "Bit 5 - Enable and disable Card Error Interrupt Summary"]
    #[inline(always)]
    #[must_use]
    pub fn ces(&mut self) -> CesW<IdintenSpec> {
        CesW::new(self, 5)
    }
    #[doc = "Bit 8 - Enable and Disable Normal Interrupt Summary"]
    #[inline(always)]
    #[must_use]
    pub fn ni(&mut self) -> NiW<IdintenSpec> {
        NiW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit enables the following bits: IDINTEN\\[2\\]
- Fatal Bus Error Interrupt IDINTEN\\[4\\]
- DU Interrupt IDINTEN\\[5\\]
- Card Error Summary Interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn ai(&mut self) -> AiW<IdintenSpec> {
        AiW::new(self, 9)
    }
}
#[doc = "Various DMA Interrupt Enable Status\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idinten::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`idinten::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdintenSpec;
impl crate::RegisterSpec for IdintenSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`idinten::R`](R) reader structure"]
impl crate::Readable for IdintenSpec {}
#[doc = "`write(|w| ..)` method takes [`idinten::W`](W) writer structure"]
impl crate::Writable for IdintenSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets idinten to value 0"]
impl crate::Resettable for IdintenSpec {
    const RESET_VALUE: u32 = 0;
}
