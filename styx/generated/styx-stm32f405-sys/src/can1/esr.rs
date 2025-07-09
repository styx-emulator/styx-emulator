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
#[doc = "Register `ESR` reader"]
pub type R = crate::R<EsrSpec>;
#[doc = "Register `ESR` writer"]
pub type W = crate::W<EsrSpec>;
#[doc = "Field `EWGF` reader - EWGF"]
pub type EwgfR = crate::BitReader;
#[doc = "Field `EWGF` writer - EWGF"]
pub type EwgfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPVF` reader - EPVF"]
pub type EpvfR = crate::BitReader;
#[doc = "Field `EPVF` writer - EPVF"]
pub type EpvfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BOFF` reader - BOFF"]
pub type BoffR = crate::BitReader;
#[doc = "Field `BOFF` writer - BOFF"]
pub type BoffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LEC` reader - LEC"]
pub type LecR = crate::FieldReader;
#[doc = "Field `LEC` writer - LEC"]
pub type LecW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `TEC` reader - TEC"]
pub type TecR = crate::FieldReader;
#[doc = "Field `TEC` writer - TEC"]
pub type TecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `REC` reader - REC"]
pub type RecR = crate::FieldReader;
#[doc = "Field `REC` writer - REC"]
pub type RecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bit 0 - EWGF"]
    #[inline(always)]
    pub fn ewgf(&self) -> EwgfR {
        EwgfR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - EPVF"]
    #[inline(always)]
    pub fn epvf(&self) -> EpvfR {
        EpvfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - BOFF"]
    #[inline(always)]
    pub fn boff(&self) -> BoffR {
        BoffR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 4:6 - LEC"]
    #[inline(always)]
    pub fn lec(&self) -> LecR {
        LecR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bits 16:23 - TEC"]
    #[inline(always)]
    pub fn tec(&self) -> TecR {
        TecR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - REC"]
    #[inline(always)]
    pub fn rec(&self) -> RecR {
        RecR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - EWGF"]
    #[inline(always)]
    #[must_use]
    pub fn ewgf(&mut self) -> EwgfW<EsrSpec> {
        EwgfW::new(self, 0)
    }
    #[doc = "Bit 1 - EPVF"]
    #[inline(always)]
    #[must_use]
    pub fn epvf(&mut self) -> EpvfW<EsrSpec> {
        EpvfW::new(self, 1)
    }
    #[doc = "Bit 2 - BOFF"]
    #[inline(always)]
    #[must_use]
    pub fn boff(&mut self) -> BoffW<EsrSpec> {
        BoffW::new(self, 2)
    }
    #[doc = "Bits 4:6 - LEC"]
    #[inline(always)]
    #[must_use]
    pub fn lec(&mut self) -> LecW<EsrSpec> {
        LecW::new(self, 4)
    }
    #[doc = "Bits 16:23 - TEC"]
    #[inline(always)]
    #[must_use]
    pub fn tec(&mut self) -> TecW<EsrSpec> {
        TecW::new(self, 16)
    }
    #[doc = "Bits 24:31 - REC"]
    #[inline(always)]
    #[must_use]
    pub fn rec(&mut self) -> RecW<EsrSpec> {
        RecW::new(self, 24)
    }
}
#[doc = "interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`esr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`esr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EsrSpec;
impl crate::RegisterSpec for EsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`esr::R`](R) reader structure"]
impl crate::Readable for EsrSpec {}
#[doc = "`write(|w| ..)` method takes [`esr::W`](W) writer structure"]
impl crate::Writable for EsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ESR to value 0"]
impl crate::Resettable for EsrSpec {
    const RESET_VALUE: u32 = 0;
}
