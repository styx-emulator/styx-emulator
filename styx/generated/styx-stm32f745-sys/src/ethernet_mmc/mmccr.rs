// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCCR` reader"]
pub type R = crate::R<MmccrSpec>;
#[doc = "Register `MMCCR` writer"]
pub type W = crate::W<MmccrSpec>;
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
    pub fn cr(&mut self) -> CrW<MmccrSpec> {
        CrW::new(self, 0)
    }
    #[doc = "Bit 1 - CSR"]
    #[inline(always)]
    #[must_use]
    pub fn csr(&mut self) -> CsrW<MmccrSpec> {
        CsrW::new(self, 1)
    }
    #[doc = "Bit 2 - ROR"]
    #[inline(always)]
    #[must_use]
    pub fn ror(&mut self) -> RorW<MmccrSpec> {
        RorW::new(self, 2)
    }
    #[doc = "Bit 3 - MCF"]
    #[inline(always)]
    #[must_use]
    pub fn mcf(&mut self) -> McfW<MmccrSpec> {
        McfW::new(self, 3)
    }
    #[doc = "Bit 4 - MCP"]
    #[inline(always)]
    #[must_use]
    pub fn mcp(&mut self) -> McpW<MmccrSpec> {
        McpW::new(self, 4)
    }
    #[doc = "Bit 5 - MCFHP"]
    #[inline(always)]
    #[must_use]
    pub fn mcfhp(&mut self) -> McfhpW<MmccrSpec> {
        McfhpW::new(self, 5)
    }
}
#[doc = "Ethernet MMC control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mmccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmccrSpec;
impl crate::RegisterSpec for MmccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`mmccr::R`](R) reader structure"]
impl crate::Readable for MmccrSpec {}
#[doc = "`write(|w| ..)` method takes [`mmccr::W`](W) writer structure"]
impl crate::Writable for MmccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MMCCR to value 0"]
impl crate::Resettable for MmccrSpec {
    const RESET_VALUE: u32 = 0;
}
