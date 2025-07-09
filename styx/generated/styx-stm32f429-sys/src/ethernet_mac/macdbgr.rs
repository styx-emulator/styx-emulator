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
#[doc = "Register `MACDBGR` reader"]
pub type R = crate::R<MacdbgrSpec>;
#[doc = "Register `MACDBGR` writer"]
pub type W = crate::W<MacdbgrSpec>;
#[doc = "Field `CR` reader - CR"]
pub type CrR = crate::BitReader;
#[doc = "Field `CR` writer - CR"]
pub type CrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSR` reader - CSR"]
pub type CsrR = crate::BitReader;
#[doc = "Field `CSR` writer - CSR"]
pub type CsrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ROR` reader - ROR"]
pub type RorR = crate::BitReader;
#[doc = "Field `ROR` writer - ROR"]
pub type RorW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MCF` reader - MCF"]
pub type McfR = crate::BitReader;
#[doc = "Field `MCF` writer - MCF"]
pub type McfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MCP` reader - MCP"]
pub type McpR = crate::BitReader;
#[doc = "Field `MCP` writer - MCP"]
pub type McpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MCFHP` reader - MCFHP"]
pub type McfhpR = crate::BitReader;
#[doc = "Field `MCFHP` writer - MCFHP"]
pub type McfhpW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - CR"]
    #[inline(always)]
    pub fn cr(&self) -> CrR {
        CrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - CSR"]
    #[inline(always)]
    pub fn csr(&self) -> CsrR {
        CsrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - ROR"]
    #[inline(always)]
    pub fn ror(&self) -> RorR {
        RorR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - MCF"]
    #[inline(always)]
    pub fn mcf(&self) -> McfR {
        McfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - MCP"]
    #[inline(always)]
    pub fn mcp(&self) -> McpR {
        McpR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - MCFHP"]
    #[inline(always)]
    pub fn mcfhp(&self) -> McfhpR {
        McfhpR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - CR"]
    #[inline(always)]
    #[must_use]
    pub fn cr(&mut self) -> CrW<MacdbgrSpec> {
        CrW::new(self, 0)
    }
    #[doc = "Bit 1 - CSR"]
    #[inline(always)]
    #[must_use]
    pub fn csr(&mut self) -> CsrW<MacdbgrSpec> {
        CsrW::new(self, 1)
    }
    #[doc = "Bit 2 - ROR"]
    #[inline(always)]
    #[must_use]
    pub fn ror(&mut self) -> RorW<MacdbgrSpec> {
        RorW::new(self, 2)
    }
    #[doc = "Bit 3 - MCF"]
    #[inline(always)]
    #[must_use]
    pub fn mcf(&mut self) -> McfW<MacdbgrSpec> {
        McfW::new(self, 3)
    }
    #[doc = "Bit 4 - MCP"]
    #[inline(always)]
    #[must_use]
    pub fn mcp(&mut self) -> McpW<MacdbgrSpec> {
        McpW::new(self, 4)
    }
    #[doc = "Bit 5 - MCFHP"]
    #[inline(always)]
    #[must_use]
    pub fn mcfhp(&mut self) -> McfhpW<MacdbgrSpec> {
        McfhpW::new(self, 5)
    }
}
#[doc = "Ethernet MAC debug register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macdbgr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacdbgrSpec;
impl crate::RegisterSpec for MacdbgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`macdbgr::R`](R) reader structure"]
impl crate::Readable for MacdbgrSpec {}
#[doc = "`reset()` method sets MACDBGR to value 0"]
impl crate::Resettable for MacdbgrSpec {
    const RESET_VALUE: u32 = 0;
}
