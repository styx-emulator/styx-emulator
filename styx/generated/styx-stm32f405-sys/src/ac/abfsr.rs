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
#[doc = "Register `ABFSR` reader"]
pub type R = crate::R<AbfsrSpec>;
#[doc = "Register `ABFSR` writer"]
pub type W = crate::W<AbfsrSpec>;
#[doc = "Field `ITCM` reader - ITCM"]
pub type ItcmR = crate::BitReader;
#[doc = "Field `ITCM` writer - ITCM"]
pub type ItcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DTCM` reader - DTCM"]
pub type DtcmR = crate::BitReader;
#[doc = "Field `DTCM` writer - DTCM"]
pub type DtcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AHBP` reader - AHBP"]
pub type AhbpR = crate::BitReader;
#[doc = "Field `AHBP` writer - AHBP"]
pub type AhbpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AXIM` reader - AXIM"]
pub type AximR = crate::BitReader;
#[doc = "Field `AXIM` writer - AXIM"]
pub type AximW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPPB` reader - EPPB"]
pub type EppbR = crate::BitReader;
#[doc = "Field `EPPB` writer - EPPB"]
pub type EppbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AXIMTYPE` reader - AXIMTYPE"]
pub type AximtypeR = crate::FieldReader;
#[doc = "Field `AXIMTYPE` writer - AXIMTYPE"]
pub type AximtypeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - ITCM"]
    #[inline(always)]
    pub fn itcm(&self) -> ItcmR {
        ItcmR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - DTCM"]
    #[inline(always)]
    pub fn dtcm(&self) -> DtcmR {
        DtcmR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - AHBP"]
    #[inline(always)]
    pub fn ahbp(&self) -> AhbpR {
        AhbpR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - AXIM"]
    #[inline(always)]
    pub fn axim(&self) -> AximR {
        AximR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - EPPB"]
    #[inline(always)]
    pub fn eppb(&self) -> EppbR {
        EppbR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 8:9 - AXIMTYPE"]
    #[inline(always)]
    pub fn aximtype(&self) -> AximtypeR {
        AximtypeR::new(((self.bits >> 8) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - ITCM"]
    #[inline(always)]
    #[must_use]
    pub fn itcm(&mut self) -> ItcmW<AbfsrSpec> {
        ItcmW::new(self, 0)
    }
    #[doc = "Bit 1 - DTCM"]
    #[inline(always)]
    #[must_use]
    pub fn dtcm(&mut self) -> DtcmW<AbfsrSpec> {
        DtcmW::new(self, 1)
    }
    #[doc = "Bit 2 - AHBP"]
    #[inline(always)]
    #[must_use]
    pub fn ahbp(&mut self) -> AhbpW<AbfsrSpec> {
        AhbpW::new(self, 2)
    }
    #[doc = "Bit 3 - AXIM"]
    #[inline(always)]
    #[must_use]
    pub fn axim(&mut self) -> AximW<AbfsrSpec> {
        AximW::new(self, 3)
    }
    #[doc = "Bit 4 - EPPB"]
    #[inline(always)]
    #[must_use]
    pub fn eppb(&mut self) -> EppbW<AbfsrSpec> {
        EppbW::new(self, 4)
    }
    #[doc = "Bits 8:9 - AXIMTYPE"]
    #[inline(always)]
    #[must_use]
    pub fn aximtype(&mut self) -> AximtypeW<AbfsrSpec> {
        AximtypeW::new(self, 8)
    }
}
#[doc = "Auxiliary Bus Fault Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`abfsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`abfsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AbfsrSpec;
impl crate::RegisterSpec for AbfsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`abfsr::R`](R) reader structure"]
impl crate::Readable for AbfsrSpec {}
#[doc = "`write(|w| ..)` method takes [`abfsr::W`](W) writer structure"]
impl crate::Writable for AbfsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ABFSR to value 0"]
impl crate::Resettable for AbfsrSpec {
    const RESET_VALUE: u32 = 0;
}
