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
#[doc = "Register `mainpllgrp_en` reader"]
pub type R = crate::R<MainpllgrpEnSpec>;
#[doc = "Register `mainpllgrp_en` writer"]
pub type W = crate::W<MainpllgrpEnSpec>;
#[doc = "Field `l4mainclk` reader - Enables clock l4_main_clk output"]
pub type L4mainclkR = crate::BitReader;
#[doc = "Field `l4mainclk` writer - Enables clock l4_main_clk output"]
pub type L4mainclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3mpclk` reader - Enables clock l3_mp_clk output"]
pub type L3mpclkR = crate::BitReader;
#[doc = "Field `l3mpclk` writer - Enables clock l3_mp_clk output"]
pub type L3mpclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4mpclk` reader - Enables clock l4_mp_clk output"]
pub type L4mpclkR = crate::BitReader;
#[doc = "Field `l4mpclk` writer - Enables clock l4_mp_clk output"]
pub type L4mpclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4spclk` reader - Enables clock l4_sp_clk output"]
pub type L4spclkR = crate::BitReader;
#[doc = "Field `l4spclk` writer - Enables clock l4_sp_clk output"]
pub type L4spclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbgatclk` reader - Enables clock dbg_at_clk output"]
pub type DbgatclkR = crate::BitReader;
#[doc = "Field `dbgatclk` writer - Enables clock dbg_at_clk output"]
pub type DbgatclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbgclk` reader - Enables clock dbg_clk output"]
pub type DbgclkR = crate::BitReader;
#[doc = "Field `dbgclk` writer - Enables clock dbg_clk output"]
pub type DbgclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbgtraceclk` reader - Enables clock dbg_trace_clk output"]
pub type DbgtraceclkR = crate::BitReader;
#[doc = "Field `dbgtraceclk` writer - Enables clock dbg_trace_clk output"]
pub type DbgtraceclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dbgtimerclk` reader - Enables clock dbg_timer_clk output"]
pub type DbgtimerclkR = crate::BitReader;
#[doc = "Field `dbgtimerclk` writer - Enables clock dbg_timer_clk output"]
pub type DbgtimerclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cfgclk` reader - Enables clock cfg_clk output"]
pub type CfgclkR = crate::BitReader;
#[doc = "Field `cfgclk` writer - Enables clock cfg_clk output"]
pub type CfgclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `s2fuser0clk` reader - Enables clock s2f_user0_clk output. Qsys and user documenation refer to s2f_user0_clk as h2f_user0_clk."]
pub type S2fuser0clkR = crate::BitReader;
#[doc = "Field `s2fuser0clk` writer - Enables clock s2f_user0_clk output. Qsys and user documenation refer to s2f_user0_clk as h2f_user0_clk."]
pub type S2fuser0clkW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enables clock l4_main_clk output"]
    #[inline(always)]
    pub fn l4mainclk(&self) -> L4mainclkR {
        L4mainclkR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Enables clock l3_mp_clk output"]
    #[inline(always)]
    pub fn l3mpclk(&self) -> L3mpclkR {
        L3mpclkR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Enables clock l4_mp_clk output"]
    #[inline(always)]
    pub fn l4mpclk(&self) -> L4mpclkR {
        L4mpclkR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Enables clock l4_sp_clk output"]
    #[inline(always)]
    pub fn l4spclk(&self) -> L4spclkR {
        L4spclkR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Enables clock dbg_at_clk output"]
    #[inline(always)]
    pub fn dbgatclk(&self) -> DbgatclkR {
        DbgatclkR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Enables clock dbg_clk output"]
    #[inline(always)]
    pub fn dbgclk(&self) -> DbgclkR {
        DbgclkR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Enables clock dbg_trace_clk output"]
    #[inline(always)]
    pub fn dbgtraceclk(&self) -> DbgtraceclkR {
        DbgtraceclkR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Enables clock dbg_timer_clk output"]
    #[inline(always)]
    pub fn dbgtimerclk(&self) -> DbgtimerclkR {
        DbgtimerclkR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Enables clock cfg_clk output"]
    #[inline(always)]
    pub fn cfgclk(&self) -> CfgclkR {
        CfgclkR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Enables clock s2f_user0_clk output. Qsys and user documenation refer to s2f_user0_clk as h2f_user0_clk."]
    #[inline(always)]
    pub fn s2fuser0clk(&self) -> S2fuser0clkR {
        S2fuser0clkR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables clock l4_main_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn l4mainclk(&mut self) -> L4mainclkW<MainpllgrpEnSpec> {
        L4mainclkW::new(self, 0)
    }
    #[doc = "Bit 1 - Enables clock l3_mp_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn l3mpclk(&mut self) -> L3mpclkW<MainpllgrpEnSpec> {
        L3mpclkW::new(self, 1)
    }
    #[doc = "Bit 2 - Enables clock l4_mp_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn l4mpclk(&mut self) -> L4mpclkW<MainpllgrpEnSpec> {
        L4mpclkW::new(self, 2)
    }
    #[doc = "Bit 3 - Enables clock l4_sp_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn l4spclk(&mut self) -> L4spclkW<MainpllgrpEnSpec> {
        L4spclkW::new(self, 3)
    }
    #[doc = "Bit 4 - Enables clock dbg_at_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn dbgatclk(&mut self) -> DbgatclkW<MainpllgrpEnSpec> {
        DbgatclkW::new(self, 4)
    }
    #[doc = "Bit 5 - Enables clock dbg_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn dbgclk(&mut self) -> DbgclkW<MainpllgrpEnSpec> {
        DbgclkW::new(self, 5)
    }
    #[doc = "Bit 6 - Enables clock dbg_trace_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn dbgtraceclk(&mut self) -> DbgtraceclkW<MainpllgrpEnSpec> {
        DbgtraceclkW::new(self, 6)
    }
    #[doc = "Bit 7 - Enables clock dbg_timer_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn dbgtimerclk(&mut self) -> DbgtimerclkW<MainpllgrpEnSpec> {
        DbgtimerclkW::new(self, 7)
    }
    #[doc = "Bit 8 - Enables clock cfg_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn cfgclk(&mut self) -> CfgclkW<MainpllgrpEnSpec> {
        CfgclkW::new(self, 8)
    }
    #[doc = "Bit 9 - Enables clock s2f_user0_clk output. Qsys and user documenation refer to s2f_user0_clk as h2f_user0_clk."]
    #[inline(always)]
    #[must_use]
    pub fn s2fuser0clk(&mut self) -> S2fuser0clkW<MainpllgrpEnSpec> {
        S2fuser0clkW::new(self, 9)
    }
}
#[doc = "Contains fields that control clock enables for clocks derived from the Main PLL. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_en::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_en::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpEnSpec;
impl crate::RegisterSpec for MainpllgrpEnSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`mainpllgrp_en::R`](R) reader structure"]
impl crate::Readable for MainpllgrpEnSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_en::W`](W) writer structure"]
impl crate::Writable for MainpllgrpEnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_en to value 0x03ff"]
impl crate::Resettable for MainpllgrpEnSpec {
    const RESET_VALUE: u32 = 0x03ff;
}
