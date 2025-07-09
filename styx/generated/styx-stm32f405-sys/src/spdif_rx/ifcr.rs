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
#[doc = "Register `IFCR` reader"]
pub type R = crate::R<IfcrSpec>;
#[doc = "Register `IFCR` writer"]
pub type W = crate::W<IfcrSpec>;
#[doc = "Field `PERRCF` reader - Clears the Parity error flag"]
pub type PerrcfR = crate::BitReader;
#[doc = "Field `PERRCF` writer - Clears the Parity error flag"]
pub type PerrcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVRCF` reader - Clears the Overrun error flag"]
pub type OvrcfR = crate::BitReader;
#[doc = "Field `OVRCF` writer - Clears the Overrun error flag"]
pub type OvrcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBDCF` reader - Clears the Synchronization Block Detected flag"]
pub type SbdcfR = crate::BitReader;
#[doc = "Field `SBDCF` writer - Clears the Synchronization Block Detected flag"]
pub type SbdcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYNCDCF` reader - Clears the Synchronization Done flag"]
pub type SyncdcfR = crate::BitReader;
#[doc = "Field `SYNCDCF` writer - Clears the Synchronization Done flag"]
pub type SyncdcfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 2 - Clears the Parity error flag"]
    #[inline(always)]
    pub fn perrcf(&self) -> PerrcfR {
        PerrcfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Clears the Overrun error flag"]
    #[inline(always)]
    pub fn ovrcf(&self) -> OvrcfR {
        OvrcfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Clears the Synchronization Block Detected flag"]
    #[inline(always)]
    pub fn sbdcf(&self) -> SbdcfR {
        SbdcfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Clears the Synchronization Done flag"]
    #[inline(always)]
    pub fn syncdcf(&self) -> SyncdcfR {
        SyncdcfR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 2 - Clears the Parity error flag"]
    #[inline(always)]
    #[must_use]
    pub fn perrcf(&mut self) -> PerrcfW<IfcrSpec> {
        PerrcfW::new(self, 2)
    }
    #[doc = "Bit 3 - Clears the Overrun error flag"]
    #[inline(always)]
    #[must_use]
    pub fn ovrcf(&mut self) -> OvrcfW<IfcrSpec> {
        OvrcfW::new(self, 3)
    }
    #[doc = "Bit 4 - Clears the Synchronization Block Detected flag"]
    #[inline(always)]
    #[must_use]
    pub fn sbdcf(&mut self) -> SbdcfW<IfcrSpec> {
        SbdcfW::new(self, 4)
    }
    #[doc = "Bit 5 - Clears the Synchronization Done flag"]
    #[inline(always)]
    #[must_use]
    pub fn syncdcf(&mut self) -> SyncdcfW<IfcrSpec> {
        SyncdcfW::new(self, 5)
    }
}
#[doc = "Interrupt Flag Clear register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ifcr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IfcrSpec;
impl crate::RegisterSpec for IfcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`write(|w| ..)` method takes [`ifcr::W`](W) writer structure"]
impl crate::Writable for IfcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets IFCR to value 0"]
impl crate::Resettable for IfcrSpec {
    const RESET_VALUE: u32 = 0;
}
