// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `perpllgrp_stat` reader"]
pub type R = crate::R<PerpllgrpStatSpec>;
#[doc = "Register `perpllgrp_stat` writer"]
pub type W = crate::W<PerpllgrpStatSpec>;
#[doc = "These read only bits per PLL output indicate that the PLL has received the Output Reset Counter request and has gracefully stopped the respective PLL output clock. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Outresetack {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    AckReceived = 1,
}
impl From<Outresetack> for u8 {
    #[inline(always)]
    fn from(variant: Outresetack) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Outresetack {
    type Ux = u8;
}
#[doc = "Field `outresetack` reader - These read only bits per PLL output indicate that the PLL has received the Output Reset Counter request and has gracefully stopped the respective PLL output clock. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type OutresetackR = crate::FieldReader<Outresetack>;
impl OutresetackR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Outresetack> {
        match self.bits {
            0 => Some(Outresetack::Idle),
            1 => Some(Outresetack::AckReceived),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == Outresetack::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ack_received(&self) -> bool {
        *self == Outresetack::AckReceived
    }
}
#[doc = "Field `outresetack` writer - These read only bits per PLL output indicate that the PLL has received the Output Reset Counter request and has gracefully stopped the respective PLL output clock. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type OutresetackW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - These read only bits per PLL output indicate that the PLL has received the Output Reset Counter request and has gracefully stopped the respective PLL output clock. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn outresetack(&self) -> OutresetackR {
        OutresetackR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - These read only bits per PLL output indicate that the PLL has received the Output Reset Counter request and has gracefully stopped the respective PLL output clock. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn outresetack(&mut self) -> OutresetackW<PerpllgrpStatSpec> {
        OutresetackW::new(self, 0)
    }
}
#[doc = "Contains Output Clock Counter Reset acknowledge status.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_stat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpStatSpec;
impl crate::RegisterSpec for PerpllgrpStatSpec {
    type Ux = u32;
    const OFFSET: u64 = 176u64;
}
#[doc = "`read()` method returns [`perpllgrp_stat::R`](R) reader structure"]
impl crate::Readable for PerpllgrpStatSpec {}
#[doc = "`reset()` method sets perpllgrp_stat to value 0"]
impl crate::Resettable for PerpllgrpStatSpec {
    const RESET_VALUE: u32 = 0;
}
