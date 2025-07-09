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
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `RXNE` reader - Read data register not empty"]
pub type RxneR = crate::BitReader;
#[doc = "Field `RXNE` writer - Read data register not empty"]
pub type RxneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSRNE` reader - Control Buffer register is not empty"]
pub type CsrneR = crate::BitReader;
#[doc = "Field `CSRNE` writer - Control Buffer register is not empty"]
pub type CsrneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PERR` reader - Parity error"]
pub type PerrR = crate::BitReader;
#[doc = "Field `PERR` writer - Parity error"]
pub type PerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR` reader - Overrun error"]
pub type OvrR = crate::BitReader;
#[doc = "Field `OVR` writer - Overrun error"]
pub type OvrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBD` reader - Synchronization Block Detected"]
pub type SbdR = crate::BitReader;
#[doc = "Field `SBD` writer - Synchronization Block Detected"]
pub type SbdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYNCD` reader - Synchronization Done"]
pub type SyncdR = crate::BitReader;
#[doc = "Field `SYNCD` writer - Synchronization Done"]
pub type SyncdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FERR` reader - Framing error"]
pub type FerrR = crate::BitReader;
#[doc = "Field `FERR` writer - Framing error"]
pub type FerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SERR` reader - Synchronization error"]
pub type SerrR = crate::BitReader;
#[doc = "Field `SERR` writer - Synchronization error"]
pub type SerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TERR` reader - Time-out error"]
pub type TerrR = crate::BitReader;
#[doc = "Field `TERR` writer - Time-out error"]
pub type TerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WIDTH5` reader - Duration of 5 symbols counted with SPDIF_CLK"]
pub type Width5R = crate::FieldReader<u16>;
#[doc = "Field `WIDTH5` writer - Duration of 5 symbols counted with SPDIF_CLK"]
pub type Width5W<'a, REG> = crate::FieldWriter<'a, REG, 15, u16>;
impl R {
    #[doc = "Bit 0 - Read data register not empty"]
    #[inline(always)]
    pub fn rxne(&self) -> RxneR {
        RxneR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Control Buffer register is not empty"]
    #[inline(always)]
    pub fn csrne(&self) -> CsrneR {
        CsrneR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Parity error"]
    #[inline(always)]
    pub fn perr(&self) -> PerrR {
        PerrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Overrun error"]
    #[inline(always)]
    pub fn ovr(&self) -> OvrR {
        OvrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Synchronization Block Detected"]
    #[inline(always)]
    pub fn sbd(&self) -> SbdR {
        SbdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Synchronization Done"]
    #[inline(always)]
    pub fn syncd(&self) -> SyncdR {
        SyncdR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Framing error"]
    #[inline(always)]
    pub fn ferr(&self) -> FerrR {
        FerrR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Synchronization error"]
    #[inline(always)]
    pub fn serr(&self) -> SerrR {
        SerrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Time-out error"]
    #[inline(always)]
    pub fn terr(&self) -> TerrR {
        TerrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bits 16:30 - Duration of 5 symbols counted with SPDIF_CLK"]
    #[inline(always)]
    pub fn width5(&self) -> Width5R {
        Width5R::new(((self.bits >> 16) & 0x7fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - Read data register not empty"]
    #[inline(always)]
    #[must_use]
    pub fn rxne(&mut self) -> RxneW<SrSpec> {
        RxneW::new(self, 0)
    }
    #[doc = "Bit 1 - Control Buffer register is not empty"]
    #[inline(always)]
    #[must_use]
    pub fn csrne(&mut self) -> CsrneW<SrSpec> {
        CsrneW::new(self, 1)
    }
    #[doc = "Bit 2 - Parity error"]
    #[inline(always)]
    #[must_use]
    pub fn perr(&mut self) -> PerrW<SrSpec> {
        PerrW::new(self, 2)
    }
    #[doc = "Bit 3 - Overrun error"]
    #[inline(always)]
    #[must_use]
    pub fn ovr(&mut self) -> OvrW<SrSpec> {
        OvrW::new(self, 3)
    }
    #[doc = "Bit 4 - Synchronization Block Detected"]
    #[inline(always)]
    #[must_use]
    pub fn sbd(&mut self) -> SbdW<SrSpec> {
        SbdW::new(self, 4)
    }
    #[doc = "Bit 5 - Synchronization Done"]
    #[inline(always)]
    #[must_use]
    pub fn syncd(&mut self) -> SyncdW<SrSpec> {
        SyncdW::new(self, 5)
    }
    #[doc = "Bit 6 - Framing error"]
    #[inline(always)]
    #[must_use]
    pub fn ferr(&mut self) -> FerrW<SrSpec> {
        FerrW::new(self, 6)
    }
    #[doc = "Bit 7 - Synchronization error"]
    #[inline(always)]
    #[must_use]
    pub fn serr(&mut self) -> SerrW<SrSpec> {
        SerrW::new(self, 7)
    }
    #[doc = "Bit 8 - Time-out error"]
    #[inline(always)]
    #[must_use]
    pub fn terr(&mut self) -> TerrW<SrSpec> {
        TerrW::new(self, 8)
    }
    #[doc = "Bits 16:30 - Duration of 5 symbols counted with SPDIF_CLK"]
    #[inline(always)]
    #[must_use]
    pub fn width5(&mut self) -> Width5W<SrSpec> {
        Width5W::new(self, 16)
    }
}
#[doc = "Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
