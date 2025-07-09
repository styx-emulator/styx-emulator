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
#[doc = "Register `FPCCR` reader"]
pub type R = crate::R<FpccrSpec>;
#[doc = "Register `FPCCR` writer"]
pub type W = crate::W<FpccrSpec>;
#[doc = "Field `LSPACT` reader - LSPACT"]
pub type LspactR = crate::BitReader;
#[doc = "Field `LSPACT` writer - LSPACT"]
pub type LspactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USER` reader - USER"]
pub type UserR = crate::BitReader;
#[doc = "Field `USER` writer - USER"]
pub type UserW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `THREAD` reader - THREAD"]
pub type ThreadR = crate::BitReader;
#[doc = "Field `THREAD` writer - THREAD"]
pub type ThreadW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HFRDY` reader - HFRDY"]
pub type HfrdyR = crate::BitReader;
#[doc = "Field `HFRDY` writer - HFRDY"]
pub type HfrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMRDY` reader - MMRDY"]
pub type MmrdyR = crate::BitReader;
#[doc = "Field `MMRDY` writer - MMRDY"]
pub type MmrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BFRDY` reader - BFRDY"]
pub type BfrdyR = crate::BitReader;
#[doc = "Field `BFRDY` writer - BFRDY"]
pub type BfrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MONRDY` reader - MONRDY"]
pub type MonrdyR = crate::BitReader;
#[doc = "Field `MONRDY` writer - MONRDY"]
pub type MonrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSPEN` reader - LSPEN"]
pub type LspenR = crate::BitReader;
#[doc = "Field `LSPEN` writer - LSPEN"]
pub type LspenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ASPEN` reader - ASPEN"]
pub type AspenR = crate::BitReader;
#[doc = "Field `ASPEN` writer - ASPEN"]
pub type AspenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - LSPACT"]
    #[inline(always)]
    pub fn lspact(&self) -> LspactR {
        LspactR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - USER"]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - THREAD"]
    #[inline(always)]
    pub fn thread(&self) -> ThreadR {
        ThreadR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - HFRDY"]
    #[inline(always)]
    pub fn hfrdy(&self) -> HfrdyR {
        HfrdyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - MMRDY"]
    #[inline(always)]
    pub fn mmrdy(&self) -> MmrdyR {
        MmrdyR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - BFRDY"]
    #[inline(always)]
    pub fn bfrdy(&self) -> BfrdyR {
        BfrdyR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - MONRDY"]
    #[inline(always)]
    pub fn monrdy(&self) -> MonrdyR {
        MonrdyR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 30 - LSPEN"]
    #[inline(always)]
    pub fn lspen(&self) -> LspenR {
        LspenR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - ASPEN"]
    #[inline(always)]
    pub fn aspen(&self) -> AspenR {
        AspenR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - LSPACT"]
    #[inline(always)]
    #[must_use]
    pub fn lspact(&mut self) -> LspactW<FpccrSpec> {
        LspactW::new(self, 0)
    }
    #[doc = "Bit 1 - USER"]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<FpccrSpec> {
        UserW::new(self, 1)
    }
    #[doc = "Bit 3 - THREAD"]
    #[inline(always)]
    #[must_use]
    pub fn thread(&mut self) -> ThreadW<FpccrSpec> {
        ThreadW::new(self, 3)
    }
    #[doc = "Bit 4 - HFRDY"]
    #[inline(always)]
    #[must_use]
    pub fn hfrdy(&mut self) -> HfrdyW<FpccrSpec> {
        HfrdyW::new(self, 4)
    }
    #[doc = "Bit 5 - MMRDY"]
    #[inline(always)]
    #[must_use]
    pub fn mmrdy(&mut self) -> MmrdyW<FpccrSpec> {
        MmrdyW::new(self, 5)
    }
    #[doc = "Bit 6 - BFRDY"]
    #[inline(always)]
    #[must_use]
    pub fn bfrdy(&mut self) -> BfrdyW<FpccrSpec> {
        BfrdyW::new(self, 6)
    }
    #[doc = "Bit 8 - MONRDY"]
    #[inline(always)]
    #[must_use]
    pub fn monrdy(&mut self) -> MonrdyW<FpccrSpec> {
        MonrdyW::new(self, 8)
    }
    #[doc = "Bit 30 - LSPEN"]
    #[inline(always)]
    #[must_use]
    pub fn lspen(&mut self) -> LspenW<FpccrSpec> {
        LspenW::new(self, 30)
    }
    #[doc = "Bit 31 - ASPEN"]
    #[inline(always)]
    #[must_use]
    pub fn aspen(&mut self) -> AspenW<FpccrSpec> {
        AspenW::new(self, 31)
    }
}
#[doc = "Floating-point context control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FpccrSpec;
impl crate::RegisterSpec for FpccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`fpccr::R`](R) reader structure"]
impl crate::Readable for FpccrSpec {}
#[doc = "`write(|w| ..)` method takes [`fpccr::W`](W) writer structure"]
impl crate::Writable for FpccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FPCCR to value 0"]
impl crate::Resettable for FpccrSpec {
    const RESET_VALUE: u32 = 0;
}
