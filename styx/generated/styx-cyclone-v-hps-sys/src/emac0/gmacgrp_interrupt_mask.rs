// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Interrupt_Mask` reader"]
pub type R = crate::R<GmacgrpInterruptMaskSpec>;
#[doc = "Register `gmacgrp_Interrupt_Mask` writer"]
pub type W = crate::W<GmacgrpInterruptMaskSpec>;
#[doc = "When set, this bit disables the assertion of the interrupt signal because of the setting of the RGMII or SMII Interrupt Status bit in Register 14 (Interrupt Status Register).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rgsmiiim {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rgsmiiim> for bool {
    #[inline(always)]
    fn from(variant: Rgsmiiim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rgsmiiim` reader - When set, this bit disables the assertion of the interrupt signal because of the setting of the RGMII or SMII Interrupt Status bit in Register 14 (Interrupt Status Register)."]
pub type RgsmiiimR = crate::BitReader<Rgsmiiim>;
impl RgsmiiimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rgsmiiim {
        match self.bits {
            false => Rgsmiiim::Disabled,
            true => Rgsmiiim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rgsmiiim::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rgsmiiim::Enabled
    }
}
#[doc = "Field `rgsmiiim` writer - When set, this bit disables the assertion of the interrupt signal because of the setting of the RGMII or SMII Interrupt Status bit in Register 14 (Interrupt Status Register)."]
pub type RgsmiiimW<'a, REG> = crate::BitWriter<'a, REG, Rgsmiiim>;
impl<'a, REG> RgsmiiimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rgsmiiim::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rgsmiiim::Enabled)
    }
}
#[doc = "Field `pcslchgim` reader - When set, this bit disables the assertion of the interrupt signal because of the setting of the PCS Link-status changed bit in Register 14 (Interrupt Status Register)."]
pub type PcslchgimR = crate::BitReader;
#[doc = "Field `pcslchgim` writer - When set, this bit disables the assertion of the interrupt signal because of the setting of the PCS Link-status changed bit in Register 14 (Interrupt Status Register)."]
pub type PcslchgimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `pcsancim` reader - When set, this bit disables the assertion of the interrupt signal because of the setting of PCS Auto-negotiation complete bit in Register 14 (Interrupt Status Register)."]
pub type PcsancimR = crate::BitReader;
#[doc = "Field `pcsancim` writer - When set, this bit disables the assertion of the interrupt signal because of the setting of PCS Auto-negotiation complete bit in Register 14 (Interrupt Status Register)."]
pub type PcsancimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit disables the assertion of the interrupt signal because of the setting of Timestamp Interrupt Status bit in Register 14 (Interrupt Status Register).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsim {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsim> for bool {
    #[inline(always)]
    fn from(variant: Tsim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsim` reader - When set, this bit disables the assertion of the interrupt signal because of the setting of Timestamp Interrupt Status bit in Register 14 (Interrupt Status Register)."]
pub type TsimR = crate::BitReader<Tsim>;
impl TsimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsim {
        match self.bits {
            false => Tsim::Disabled,
            true => Tsim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsim::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsim::Enabled
    }
}
#[doc = "Field `tsim` writer - When set, this bit disables the assertion of the interrupt signal because of the setting of Timestamp Interrupt Status bit in Register 14 (Interrupt Status Register)."]
pub type TsimW<'a, REG> = crate::BitWriter<'a, REG, Tsim>;
impl<'a, REG> TsimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsim::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsim::Enabled)
    }
}
#[doc = "When set, this bit disables the assertion of the interrupt signal because of the setting of the LPI Interrupt Status bit in Register 14 (Interrupt Status Register).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lpiim {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lpiim> for bool {
    #[inline(always)]
    fn from(variant: Lpiim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lpiim` reader - When set, this bit disables the assertion of the interrupt signal because of the setting of the LPI Interrupt Status bit in Register 14 (Interrupt Status Register)."]
pub type LpiimR = crate::BitReader<Lpiim>;
impl LpiimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lpiim {
        match self.bits {
            false => Lpiim::Disabled,
            true => Lpiim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lpiim::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lpiim::Enabled
    }
}
#[doc = "Field `lpiim` writer - When set, this bit disables the assertion of the interrupt signal because of the setting of the LPI Interrupt Status bit in Register 14 (Interrupt Status Register)."]
pub type LpiimW<'a, REG> = crate::BitWriter<'a, REG, Lpiim>;
impl<'a, REG> LpiimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lpiim::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lpiim::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When set, this bit disables the assertion of the interrupt signal because of the setting of the RGMII or SMII Interrupt Status bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    pub fn rgsmiiim(&self) -> RgsmiiimR {
        RgsmiiimR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set, this bit disables the assertion of the interrupt signal because of the setting of the PCS Link-status changed bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    pub fn pcslchgim(&self) -> PcslchgimR {
        PcslchgimR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When set, this bit disables the assertion of the interrupt signal because of the setting of PCS Auto-negotiation complete bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    pub fn pcsancim(&self) -> PcsancimR {
        PcsancimR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 9 - When set, this bit disables the assertion of the interrupt signal because of the setting of Timestamp Interrupt Status bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    pub fn tsim(&self) -> TsimR {
        TsimR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - When set, this bit disables the assertion of the interrupt signal because of the setting of the LPI Interrupt Status bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    pub fn lpiim(&self) -> LpiimR {
        LpiimR::new(((self.bits >> 10) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set, this bit disables the assertion of the interrupt signal because of the setting of the RGMII or SMII Interrupt Status bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    #[must_use]
    pub fn rgsmiiim(&mut self) -> RgsmiiimW<GmacgrpInterruptMaskSpec> {
        RgsmiiimW::new(self, 0)
    }
    #[doc = "Bit 1 - When set, this bit disables the assertion of the interrupt signal because of the setting of the PCS Link-status changed bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    #[must_use]
    pub fn pcslchgim(&mut self) -> PcslchgimW<GmacgrpInterruptMaskSpec> {
        PcslchgimW::new(self, 1)
    }
    #[doc = "Bit 2 - When set, this bit disables the assertion of the interrupt signal because of the setting of PCS Auto-negotiation complete bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    #[must_use]
    pub fn pcsancim(&mut self) -> PcsancimW<GmacgrpInterruptMaskSpec> {
        PcsancimW::new(self, 2)
    }
    #[doc = "Bit 9 - When set, this bit disables the assertion of the interrupt signal because of the setting of Timestamp Interrupt Status bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    #[must_use]
    pub fn tsim(&mut self) -> TsimW<GmacgrpInterruptMaskSpec> {
        TsimW::new(self, 9)
    }
    #[doc = "Bit 10 - When set, this bit disables the assertion of the interrupt signal because of the setting of the LPI Interrupt Status bit in Register 14 (Interrupt Status Register)."]
    #[inline(always)]
    #[must_use]
    pub fn lpiim(&mut self) -> LpiimW<GmacgrpInterruptMaskSpec> {
        LpiimW::new(self, 10)
    }
}
#[doc = "The Interrupt Mask Register bits enable you to mask the interrupt signal because of the corresponding event in the Interrupt Status Register. The interrupt signal is sbd_intr_o.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_interrupt_mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_interrupt_mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpInterruptMaskSpec;
impl crate::RegisterSpec for GmacgrpInterruptMaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`gmacgrp_interrupt_mask::R`](R) reader structure"]
impl crate::Readable for GmacgrpInterruptMaskSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_interrupt_mask::W`](W) writer structure"]
impl crate::Writable for GmacgrpInterruptMaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Interrupt_Mask to value 0"]
impl crate::Resettable for GmacgrpInterruptMaskSpec {
    const RESET_VALUE: u32 = 0;
}
