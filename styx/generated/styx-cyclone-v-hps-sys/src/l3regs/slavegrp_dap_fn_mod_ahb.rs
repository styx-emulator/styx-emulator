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
#[doc = "Register `slavegrp_dap_fn_mod_ahb` reader"]
pub type R = crate::R<SlavegrpDapFnModAhbSpec>;
#[doc = "Register `slavegrp_dap_fn_mod_ahb` writer"]
pub type W = crate::W<SlavegrpDapFnModAhbSpec>;
#[doc = "Controls how AHB-lite read burst transactions are converted to AXI tranactions.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RdIncrOverride {
    #[doc = "0: `0`"]
    Default = 0,
    #[doc = "1: `1`"]
    Singles = 1,
}
impl From<RdIncrOverride> for bool {
    #[inline(always)]
    fn from(variant: RdIncrOverride) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rd_incr_override` reader - Controls how AHB-lite read burst transactions are converted to AXI tranactions."]
pub type RdIncrOverrideR = crate::BitReader<RdIncrOverride>;
impl RdIncrOverrideR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> RdIncrOverride {
        match self.bits {
            false => RdIncrOverride::Default,
            true => RdIncrOverride::Singles,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_default(&self) -> bool {
        *self == RdIncrOverride::Default
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_singles(&self) -> bool {
        *self == RdIncrOverride::Singles
    }
}
#[doc = "Field `rd_incr_override` writer - Controls how AHB-lite read burst transactions are converted to AXI tranactions."]
pub type RdIncrOverrideW<'a, REG> = crate::BitWriter<'a, REG, RdIncrOverride>;
impl<'a, REG> RdIncrOverrideW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn default(self) -> &'a mut crate::W<REG> {
        self.variant(RdIncrOverride::Default)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn singles(self) -> &'a mut crate::W<REG> {
        self.variant(RdIncrOverride::Singles)
    }
}
#[doc = "Controls how AHB-lite write burst transactions are converted to AXI tranactions.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrIncrOverride {
    #[doc = "0: `0`"]
    Default = 0,
    #[doc = "1: `1`"]
    Singles = 1,
}
impl From<WrIncrOverride> for bool {
    #[inline(always)]
    fn from(variant: WrIncrOverride) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wr_incr_override` reader - Controls how AHB-lite write burst transactions are converted to AXI tranactions."]
pub type WrIncrOverrideR = crate::BitReader<WrIncrOverride>;
impl WrIncrOverrideR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> WrIncrOverride {
        match self.bits {
            false => WrIncrOverride::Default,
            true => WrIncrOverride::Singles,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_default(&self) -> bool {
        *self == WrIncrOverride::Default
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_singles(&self) -> bool {
        *self == WrIncrOverride::Singles
    }
}
#[doc = "Field `wr_incr_override` writer - Controls how AHB-lite write burst transactions are converted to AXI tranactions."]
pub type WrIncrOverrideW<'a, REG> = crate::BitWriter<'a, REG, WrIncrOverride>;
impl<'a, REG> WrIncrOverrideW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn default(self) -> &'a mut crate::W<REG> {
        self.variant(WrIncrOverride::Default)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn singles(self) -> &'a mut crate::W<REG> {
        self.variant(WrIncrOverride::Singles)
    }
}
impl R {
    #[doc = "Bit 0 - Controls how AHB-lite read burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    pub fn rd_incr_override(&self) -> RdIncrOverrideR {
        RdIncrOverrideR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls how AHB-lite write burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    pub fn wr_incr_override(&self) -> WrIncrOverrideR {
        WrIncrOverrideR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls how AHB-lite read burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    #[must_use]
    pub fn rd_incr_override(&mut self) -> RdIncrOverrideW<SlavegrpDapFnModAhbSpec> {
        RdIncrOverrideW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls how AHB-lite write burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    #[must_use]
    pub fn wr_incr_override(&mut self) -> WrIncrOverrideW<SlavegrpDapFnModAhbSpec> {
        WrIncrOverrideW::new(self, 1)
    }
}
#[doc = "Controls how AHB-lite burst transactions are converted to AXI tranactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_fn_mod_ahb::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_fn_mod_ahb::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SlavegrpDapFnModAhbSpec;
impl crate::RegisterSpec for SlavegrpDapFnModAhbSpec {
    type Ux = u32;
    const OFFSET: u64 = 270376u64;
}
#[doc = "`read()` method returns [`slavegrp_dap_fn_mod_ahb::R`](R) reader structure"]
impl crate::Readable for SlavegrpDapFnModAhbSpec {}
#[doc = "`write(|w| ..)` method takes [`slavegrp_dap_fn_mod_ahb::W`](W) writer structure"]
impl crate::Writable for SlavegrpDapFnModAhbSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets slavegrp_dap_fn_mod_ahb to value 0"]
impl crate::Resettable for SlavegrpDapFnModAhbSpec {
    const RESET_VALUE: u32 = 0;
}
