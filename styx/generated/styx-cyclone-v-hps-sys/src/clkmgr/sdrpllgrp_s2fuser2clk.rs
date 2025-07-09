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
#[doc = "Register `sdrpllgrp_s2fuser2clk` reader"]
pub type R = crate::R<SdrpllgrpS2fuser2clkSpec>;
#[doc = "Register `sdrpllgrp_s2fuser2clk` writer"]
pub type W = crate::W<SdrpllgrpS2fuser2clkSpec>;
#[doc = "Field `cnt` reader - Divides the VCO frequency by the value+1 in this field."]
pub type CntR = crate::FieldReader<u16>;
#[doc = "Field `cnt` writer - Divides the VCO frequency by the value+1 in this field."]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `phase` reader - Increment the phase of the VCO output by the value in this field multiplied by 45 degrees. The accumulated phase shift is the total shifted amount since the last assertion of the 'SDRAM All Output Divider Reset' bit in the SDRAM vco control register. In order to guarantee the phase shift to a known value, 'SDRAM clocks output phase align' bit should be asserted before programming this field. This field is only writeable by SW when it is zero. HW updates this field in real time as the phase adjustment is being made. SW may poll this field waiting for zero indicating the phase adjustment has completed by HW."]
pub type PhaseR = crate::FieldReader<u16>;
#[doc = "Field `phase` writer - Increment the phase of the VCO output by the value in this field multiplied by 45 degrees. The accumulated phase shift is the total shifted amount since the last assertion of the 'SDRAM All Output Divider Reset' bit in the SDRAM vco control register. In order to guarantee the phase shift to a known value, 'SDRAM clocks output phase align' bit should be asserted before programming this field. This field is only writeable by SW when it is zero. HW updates this field in real time as the phase adjustment is being made. SW may poll this field waiting for zero indicating the phase adjustment has completed by HW."]
pub type PhaseW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:8 - Divides the VCO frequency by the value+1 in this field."]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new((self.bits & 0x01ff) as u16)
    }
    #[doc = "Bits 9:20 - Increment the phase of the VCO output by the value in this field multiplied by 45 degrees. The accumulated phase shift is the total shifted amount since the last assertion of the 'SDRAM All Output Divider Reset' bit in the SDRAM vco control register. In order to guarantee the phase shift to a known value, 'SDRAM clocks output phase align' bit should be asserted before programming this field. This field is only writeable by SW when it is zero. HW updates this field in real time as the phase adjustment is being made. SW may poll this field waiting for zero indicating the phase adjustment has completed by HW."]
    #[inline(always)]
    pub fn phase(&self) -> PhaseR {
        PhaseR::new(((self.bits >> 9) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Divides the VCO frequency by the value+1 in this field."]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<SdrpllgrpS2fuser2clkSpec> {
        CntW::new(self, 0)
    }
    #[doc = "Bits 9:20 - Increment the phase of the VCO output by the value in this field multiplied by 45 degrees. The accumulated phase shift is the total shifted amount since the last assertion of the 'SDRAM All Output Divider Reset' bit in the SDRAM vco control register. In order to guarantee the phase shift to a known value, 'SDRAM clocks output phase align' bit should be asserted before programming this field. This field is only writeable by SW when it is zero. HW updates this field in real time as the phase adjustment is being made. SW may poll this field waiting for zero indicating the phase adjustment has completed by HW."]
    #[inline(always)]
    #[must_use]
    pub fn phase(&mut self) -> PhaseW<SdrpllgrpS2fuser2clkSpec> {
        PhaseW::new(self, 9)
    }
}
#[doc = "Contains settings that control clock s2f_user2_clk generated from the C5 output of the SDRAM PLL. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_s2fuser2clk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_s2fuser2clk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdrpllgrpS2fuser2clkSpec;
impl crate::RegisterSpec for SdrpllgrpS2fuser2clkSpec {
    type Ux = u32;
    const OFFSET: u64 = 212u64;
}
#[doc = "`read()` method returns [`sdrpllgrp_s2fuser2clk::R`](R) reader structure"]
impl crate::Readable for SdrpllgrpS2fuser2clkSpec {}
#[doc = "`write(|w| ..)` method takes [`sdrpllgrp_s2fuser2clk::W`](W) writer structure"]
impl crate::Writable for SdrpllgrpS2fuser2clkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sdrpllgrp_s2fuser2clk to value 0x01"]
impl crate::Resettable for SdrpllgrpS2fuser2clkSpec {
    const RESET_VALUE: u32 = 0x01;
}
