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
#[doc = "Register `sdrpllgrp_vco` reader"]
pub type R = crate::R<SdrpllgrpVcoSpec>;
#[doc = "Register `sdrpllgrp_vco` writer"]
pub type W = crate::W<SdrpllgrpVcoSpec>;
#[doc = "Field `bgpwrdn` reader - If '1', powers down bandgap. If '0', bandgap is not power down."]
pub type BgpwrdnR = crate::BitReader;
#[doc = "Field `bgpwrdn` writer - If '1', powers down bandgap. If '0', bandgap is not power down."]
pub type BgpwrdnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `en` reader - If '1', VCO is enabled. If '0', VCO is in reset."]
pub type EnR = crate::BitReader;
#[doc = "Field `en` writer - If '1', VCO is enabled. If '0', VCO is in reset."]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `pwrdn` reader - If '1', power down analog circuitry. If '0', analog circuitry not powered down."]
pub type PwrdnR = crate::BitReader;
#[doc = "Field `pwrdn` writer - If '1', power down analog circuitry. If '0', analog circuitry not powered down."]
pub type PwrdnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `numer` reader - Numerator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
pub type NumerR = crate::FieldReader<u16>;
#[doc = "Field `numer` writer - Numerator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
pub type NumerW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
#[doc = "Field `denom` reader - Denominator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
pub type DenomR = crate::FieldReader;
#[doc = "Field `denom` writer - Denominator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
pub type DenomW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Controls the VCO input clock source. The PLL must by bypassed to eosc1_clk before changing this field. Qsys and user documenation refer to f2s_sdram_ref_clk as f2h_sdram_ref_clk.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ssrc {
    #[doc = "0: `0`"]
    Eosc1 = 0,
    #[doc = "1: `1`"]
    Eosc2 = 1,
    #[doc = "2: `10`"]
    F2sSdramRef = 2,
}
impl From<Ssrc> for u8 {
    #[inline(always)]
    fn from(variant: Ssrc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ssrc {
    type Ux = u8;
}
#[doc = "Field `ssrc` reader - Controls the VCO input clock source. The PLL must by bypassed to eosc1_clk before changing this field. Qsys and user documenation refer to f2s_sdram_ref_clk as f2h_sdram_ref_clk."]
pub type SsrcR = crate::FieldReader<Ssrc>;
impl SsrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ssrc> {
        match self.bits {
            0 => Some(Ssrc::Eosc1),
            1 => Some(Ssrc::Eosc2),
            2 => Some(Ssrc::F2sSdramRef),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_eosc1(&self) -> bool {
        *self == Ssrc::Eosc1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_eosc2(&self) -> bool {
        *self == Ssrc::Eosc2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_f2s_sdram_ref(&self) -> bool {
        *self == Ssrc::F2sSdramRef
    }
}
#[doc = "Field `ssrc` writer - Controls the VCO input clock source. The PLL must by bypassed to eosc1_clk before changing this field. Qsys and user documenation refer to f2s_sdram_ref_clk as f2h_sdram_ref_clk."]
pub type SsrcW<'a, REG> = crate::FieldWriter<'a, REG, 2, Ssrc>;
impl<'a, REG> SsrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn eosc1(self) -> &'a mut crate::W<REG> {
        self.variant(Ssrc::Eosc1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn eosc2(self) -> &'a mut crate::W<REG> {
        self.variant(Ssrc::Eosc2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn f2s_sdram_ref(self) -> &'a mut crate::W<REG> {
        self.variant(Ssrc::F2sSdramRef)
    }
}
#[doc = "Field `outresetall` reader - Before releasing Bypass, All Output Counter Reset must be set and cleared by software for correct clock operation. If '1', Reset phase multiplexer and output counter state. So that after the assertion all the clocks output are start from rising edge align. If '0', phase multiplexer and output counter state not reset and no change to the phase of the clock outputs."]
pub type OutresetallR = crate::BitReader;
#[doc = "Field `outresetall` writer - Before releasing Bypass, All Output Counter Reset must be set and cleared by software for correct clock operation. If '1', Reset phase multiplexer and output counter state. So that after the assertion all the clocks output are start from rising edge align. If '0', phase multiplexer and output counter state not reset and no change to the phase of the clock outputs."]
pub type OutresetallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `outreset` reader - Resets the individual PLL output counter. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. LSB 'outreset\\[0\\]' corresponds to PLL output clock C0, etc. If set to '1', reset output divider, no clock output from counter. If set to '0', counter is not reset. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type OutresetR = crate::FieldReader;
#[doc = "Field `outreset` writer - Resets the individual PLL output counter. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. LSB 'outreset\\[0\\]' corresponds to PLL output clock C0, etc. If set to '1', reset output divider, no clock output from counter. If set to '0', counter is not reset. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type OutresetW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `regextsel` reader - If set to '1', the external regulator is selected for the PLL. If set to '0', the internal regulator is slected. It is strongly recommended to select the external regulator while the PLL is not enabled (in reset), and then disable the external regulater once the PLL becomes enabled. Software should simulateously update the 'Enable' bit and the 'External Regulator Input Select' in the same write access to the VCO register. When the 'Enable' bit is clear, the 'External Regulator Input Select' should be set, and vice versa. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type RegextselR = crate::BitReader;
#[doc = "Field `regextsel` writer - If set to '1', the external regulator is selected for the PLL. If set to '0', the internal regulator is slected. It is strongly recommended to select the external regulator while the PLL is not enabled (in reset), and then disable the external regulater once the PLL becomes enabled. Software should simulateously update the 'Enable' bit and the 'External Regulator Input Select' in the same write access to the VCO register. When the 'Enable' bit is clear, the 'External Regulator Input Select' should be set, and vice versa. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type RegextselW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - If '1', powers down bandgap. If '0', bandgap is not power down."]
    #[inline(always)]
    pub fn bgpwrdn(&self) -> BgpwrdnR {
        BgpwrdnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - If '1', VCO is enabled. If '0', VCO is in reset."]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - If '1', power down analog circuitry. If '0', analog circuitry not powered down."]
    #[inline(always)]
    pub fn pwrdn(&self) -> PwrdnR {
        PwrdnR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:15 - Numerator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
    #[inline(always)]
    pub fn numer(&self) -> NumerR {
        NumerR::new(((self.bits >> 3) & 0x1fff) as u16)
    }
    #[doc = "Bits 16:21 - Denominator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
    #[inline(always)]
    pub fn denom(&self) -> DenomR {
        DenomR::new(((self.bits >> 16) & 0x3f) as u8)
    }
    #[doc = "Bits 22:23 - Controls the VCO input clock source. The PLL must by bypassed to eosc1_clk before changing this field. Qsys and user documenation refer to f2s_sdram_ref_clk as f2h_sdram_ref_clk."]
    #[inline(always)]
    pub fn ssrc(&self) -> SsrcR {
        SsrcR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bit 24 - Before releasing Bypass, All Output Counter Reset must be set and cleared by software for correct clock operation. If '1', Reset phase multiplexer and output counter state. So that after the assertion all the clocks output are start from rising edge align. If '0', phase multiplexer and output counter state not reset and no change to the phase of the clock outputs."]
    #[inline(always)]
    pub fn outresetall(&self) -> OutresetallR {
        OutresetallR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bits 25:30 - Resets the individual PLL output counter. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. LSB 'outreset\\[0\\]' corresponds to PLL output clock C0, etc. If set to '1', reset output divider, no clock output from counter. If set to '0', counter is not reset. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn outreset(&self) -> OutresetR {
        OutresetR::new(((self.bits >> 25) & 0x3f) as u8)
    }
    #[doc = "Bit 31 - If set to '1', the external regulator is selected for the PLL. If set to '0', the internal regulator is slected. It is strongly recommended to select the external regulator while the PLL is not enabled (in reset), and then disable the external regulater once the PLL becomes enabled. Software should simulateously update the 'Enable' bit and the 'External Regulator Input Select' in the same write access to the VCO register. When the 'Enable' bit is clear, the 'External Regulator Input Select' should be set, and vice versa. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn regextsel(&self) -> RegextselR {
        RegextselR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - If '1', powers down bandgap. If '0', bandgap is not power down."]
    #[inline(always)]
    #[must_use]
    pub fn bgpwrdn(&mut self) -> BgpwrdnW<SdrpllgrpVcoSpec> {
        BgpwrdnW::new(self, 0)
    }
    #[doc = "Bit 1 - If '1', VCO is enabled. If '0', VCO is in reset."]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<SdrpllgrpVcoSpec> {
        EnW::new(self, 1)
    }
    #[doc = "Bit 2 - If '1', power down analog circuitry. If '0', analog circuitry not powered down."]
    #[inline(always)]
    #[must_use]
    pub fn pwrdn(&mut self) -> PwrdnW<SdrpllgrpVcoSpec> {
        PwrdnW::new(self, 2)
    }
    #[doc = "Bits 3:15 - Numerator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
    #[inline(always)]
    #[must_use]
    pub fn numer(&mut self) -> NumerW<SdrpllgrpVcoSpec> {
        NumerW::new(self, 3)
    }
    #[doc = "Bits 16:21 - Denominator in VCO output frequency equation. For incremental frequency change, if the new value lead to less than 20% of the frequency change, this value can be changed without resetting the PLL. The Numerator and Denominator can not be changed at the same time for incremental frequency changed."]
    #[inline(always)]
    #[must_use]
    pub fn denom(&mut self) -> DenomW<SdrpllgrpVcoSpec> {
        DenomW::new(self, 16)
    }
    #[doc = "Bits 22:23 - Controls the VCO input clock source. The PLL must by bypassed to eosc1_clk before changing this field. Qsys and user documenation refer to f2s_sdram_ref_clk as f2h_sdram_ref_clk."]
    #[inline(always)]
    #[must_use]
    pub fn ssrc(&mut self) -> SsrcW<SdrpllgrpVcoSpec> {
        SsrcW::new(self, 22)
    }
    #[doc = "Bit 24 - Before releasing Bypass, All Output Counter Reset must be set and cleared by software for correct clock operation. If '1', Reset phase multiplexer and output counter state. So that after the assertion all the clocks output are start from rising edge align. If '0', phase multiplexer and output counter state not reset and no change to the phase of the clock outputs."]
    #[inline(always)]
    #[must_use]
    pub fn outresetall(&mut self) -> OutresetallW<SdrpllgrpVcoSpec> {
        OutresetallW::new(self, 24)
    }
    #[doc = "Bits 25:30 - Resets the individual PLL output counter. For software to change the PLL output counter without producing glitches on the respective clock, SW must set the VCO register respective Output Counter Reset bit. Software then polls the respective Output Counter Reset Acknowledge bit in the Output Counter Reset Ack Status Register. Software then writes the appropriate counter register, and then clears the respective VCO register Output Counter Reset bit. LSB 'outreset\\[0\\]' corresponds to PLL output clock C0, etc. If set to '1', reset output divider, no clock output from counter. If set to '0', counter is not reset. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn outreset(&mut self) -> OutresetW<SdrpllgrpVcoSpec> {
        OutresetW::new(self, 25)
    }
    #[doc = "Bit 31 - If set to '1', the external regulator is selected for the PLL. If set to '0', the internal regulator is slected. It is strongly recommended to select the external regulator while the PLL is not enabled (in reset), and then disable the external regulater once the PLL becomes enabled. Software should simulateously update the 'Enable' bit and the 'External Regulator Input Select' in the same write access to the VCO register. When the 'Enable' bit is clear, the 'External Regulator Input Select' should be set, and vice versa. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn regextsel(&mut self) -> RegextselW<SdrpllgrpVcoSpec> {
        RegextselW::new(self, 31)
    }
}
#[doc = "Contains settings that control the SDRAM PLL VCO. The VCO output frequency is the input frequency multiplied by the numerator (M+1) and divided by the denominator (N+1). Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_vco::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_vco::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdrpllgrpVcoSpec;
impl crate::RegisterSpec for SdrpllgrpVcoSpec {
    type Ux = u32;
    const OFFSET: u64 = 192u64;
}
#[doc = "`read()` method returns [`sdrpllgrp_vco::R`](R) reader structure"]
impl crate::Readable for SdrpllgrpVcoSpec {}
#[doc = "`write(|w| ..)` method takes [`sdrpllgrp_vco::W`](W) writer structure"]
impl crate::Writable for SdrpllgrpVcoSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sdrpllgrp_vco to value 0x8001_000d"]
impl crate::Resettable for SdrpllgrpVcoSpec {
    const RESET_VALUE: u32 = 0x8001_000d;
}
