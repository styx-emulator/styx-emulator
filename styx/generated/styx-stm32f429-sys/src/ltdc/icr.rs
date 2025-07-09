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
#[doc = "Register `ICR` reader"]
pub type R = crate::R<IcrSpec>;
#[doc = "Register `ICR` writer"]
pub type W = crate::W<IcrSpec>;
#[doc = "Field `CLIF` reader - Clears the Line Interrupt Flag"]
pub type ClifR = crate::BitReader;
#[doc = "Field `CLIF` writer - Clears the Line Interrupt Flag"]
pub type ClifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFUIF` reader - Clears the FIFO Underrun Interrupt flag"]
pub type CfuifR = crate::BitReader;
#[doc = "Field `CFUIF` writer - Clears the FIFO Underrun Interrupt flag"]
pub type CfuifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTERRIF` reader - Clears the Transfer Error Interrupt Flag"]
pub type CterrifR = crate::BitReader;
#[doc = "Field `CTERRIF` writer - Clears the Transfer Error Interrupt Flag"]
pub type CterrifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CRRIF` reader - Clears Register Reload Interrupt Flag"]
pub type CrrifR = crate::BitReader;
#[doc = "Field `CRRIF` writer - Clears Register Reload Interrupt Flag"]
pub type CrrifW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clears the Line Interrupt Flag"]
    #[inline(always)]
    pub fn clif(&self) -> ClifR {
        ClifR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Clears the FIFO Underrun Interrupt flag"]
    #[inline(always)]
    pub fn cfuif(&self) -> CfuifR {
        CfuifR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Clears the Transfer Error Interrupt Flag"]
    #[inline(always)]
    pub fn cterrif(&self) -> CterrifR {
        CterrifR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Clears Register Reload Interrupt Flag"]
    #[inline(always)]
    pub fn crrif(&self) -> CrrifR {
        CrrifR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clears the Line Interrupt Flag"]
    #[inline(always)]
    #[must_use]
    pub fn clif(&mut self) -> ClifW<IcrSpec> {
        ClifW::new(self, 0)
    }
    #[doc = "Bit 1 - Clears the FIFO Underrun Interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn cfuif(&mut self) -> CfuifW<IcrSpec> {
        CfuifW::new(self, 1)
    }
    #[doc = "Bit 2 - Clears the Transfer Error Interrupt Flag"]
    #[inline(always)]
    #[must_use]
    pub fn cterrif(&mut self) -> CterrifW<IcrSpec> {
        CterrifW::new(self, 2)
    }
    #[doc = "Bit 3 - Clears Register Reload Interrupt Flag"]
    #[inline(always)]
    #[must_use]
    pub fn crrif(&mut self) -> CrrifW<IcrSpec> {
        CrrifW::new(self, 3)
    }
}
#[doc = "Interrupt Clear Register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcrSpec;
impl crate::RegisterSpec for IcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`write(|w| ..)` method takes [`icr::W`](W) writer structure"]
impl crate::Writable for IcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ICR to value 0"]
impl crate::Resettable for IcrSpec {
    const RESET_VALUE: u32 = 0;
}
