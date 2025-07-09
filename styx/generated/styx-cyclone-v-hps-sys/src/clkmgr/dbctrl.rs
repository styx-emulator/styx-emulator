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
#[doc = "Register `dbctrl` reader"]
pub type R = crate::R<DbctrlSpec>;
#[doc = "Register `dbctrl` writer"]
pub type W = crate::W<DbctrlSpec>;
#[doc = "Field `stayosc1` reader - When this bit is set the debug root clock (Main PLL C2 output) will always be bypassed to the EOSC1_clk independent of any other clock manager settings. When clear the debug source will be a function of register settings in the clock manager. Clocks affected by this bit are dbg_at_clk, dbg_clk, dbg_trace_clk, and dbg_timer_clk. The reset value for this bit is applied on a cold reset. Warm reset has no affect on this bit."]
pub type Stayosc1R = crate::BitReader;
#[doc = "Field `stayosc1` writer - When this bit is set the debug root clock (Main PLL C2 output) will always be bypassed to the EOSC1_clk independent of any other clock manager settings. When clear the debug source will be a function of register settings in the clock manager. Clocks affected by this bit are dbg_at_clk, dbg_clk, dbg_trace_clk, and dbg_timer_clk. The reset value for this bit is applied on a cold reset. Warm reset has no affect on this bit."]
pub type Stayosc1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ensfmdwr` reader - When this bit is set the debug clocks will be affected by the assertion of Safe Mode on a warm reset if Stay OSC1 is not set. When this bit is clear the debug clocks will not be affected by the assertion of Safe Mode on a warm reset. If Debug Clocks are in Safe Mode they are taken out of Safe Mode when the Safe Mode bit is cleared independent of this bit.The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type EnsfmdwrR = crate::BitReader;
#[doc = "Field `ensfmdwr` writer - When this bit is set the debug clocks will be affected by the assertion of Safe Mode on a warm reset if Stay OSC1 is not set. When this bit is clear the debug clocks will not be affected by the assertion of Safe Mode on a warm reset. If Debug Clocks are in Safe Mode they are taken out of Safe Mode when the Safe Mode bit is cleared independent of this bit.The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type EnsfmdwrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When this bit is set the debug root clock (Main PLL C2 output) will always be bypassed to the EOSC1_clk independent of any other clock manager settings. When clear the debug source will be a function of register settings in the clock manager. Clocks affected by this bit are dbg_at_clk, dbg_clk, dbg_trace_clk, and dbg_timer_clk. The reset value for this bit is applied on a cold reset. Warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn stayosc1(&self) -> Stayosc1R {
        Stayosc1R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When this bit is set the debug clocks will be affected by the assertion of Safe Mode on a warm reset if Stay OSC1 is not set. When this bit is clear the debug clocks will not be affected by the assertion of Safe Mode on a warm reset. If Debug Clocks are in Safe Mode they are taken out of Safe Mode when the Safe Mode bit is cleared independent of this bit.The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn ensfmdwr(&self) -> EnsfmdwrR {
        EnsfmdwrR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is set the debug root clock (Main PLL C2 output) will always be bypassed to the EOSC1_clk independent of any other clock manager settings. When clear the debug source will be a function of register settings in the clock manager. Clocks affected by this bit are dbg_at_clk, dbg_clk, dbg_trace_clk, and dbg_timer_clk. The reset value for this bit is applied on a cold reset. Warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn stayosc1(&mut self) -> Stayosc1W<DbctrlSpec> {
        Stayosc1W::new(self, 0)
    }
    #[doc = "Bit 1 - When this bit is set the debug clocks will be affected by the assertion of Safe Mode on a warm reset if Stay OSC1 is not set. When this bit is clear the debug clocks will not be affected by the assertion of Safe Mode on a warm reset. If Debug Clocks are in Safe Mode they are taken out of Safe Mode when the Safe Mode bit is cleared independent of this bit.The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn ensfmdwr(&mut self) -> EnsfmdwrW<DbctrlSpec> {
        EnsfmdwrW::new(self, 1)
    }
}
#[doc = "Contains fields that control the debug clocks.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DbctrlSpec;
impl crate::RegisterSpec for DbctrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`dbctrl::R`](R) reader structure"]
impl crate::Readable for DbctrlSpec {}
#[doc = "`write(|w| ..)` method takes [`dbctrl::W`](W) writer structure"]
impl crate::Writable for DbctrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dbctrl to value 0x03"]
impl crate::Resettable for DbctrlSpec {
    const RESET_VALUE: u32 = 0x03;
}
