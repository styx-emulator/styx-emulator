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
#[doc = "Register `PLLI2SCFGR` reader"]
pub type R = crate::R<Plli2scfgrSpec>;
#[doc = "Register `PLLI2SCFGR` writer"]
pub type W = crate::W<Plli2scfgrSpec>;
#[doc = "Field `PLLI2SN` reader - PLLI2S multiplication factor for VCO"]
pub type Plli2snR = crate::FieldReader<u16>;
#[doc = "Field `PLLI2SN` writer - PLLI2S multiplication factor for VCO"]
pub type Plli2snW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `PLLI2SQ` reader - PLLI2S division factor for SAI1 clock"]
pub type Plli2sqR = crate::FieldReader;
#[doc = "Field `PLLI2SQ` writer - PLLI2S division factor for SAI1 clock"]
pub type Plli2sqW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PLLI2SR` reader - PLLI2S division factor for I2S clocks"]
pub type Plli2srR = crate::FieldReader;
#[doc = "Field `PLLI2SR` writer - PLLI2S division factor for I2S clocks"]
pub type Plli2srW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 6:14 - PLLI2S multiplication factor for VCO"]
    #[inline(always)]
    pub fn plli2sn(&self) -> Plli2snR {
        Plli2snR::new(((self.bits >> 6) & 0x01ff) as u16)
    }
    #[doc = "Bits 24:27 - PLLI2S division factor for SAI1 clock"]
    #[inline(always)]
    pub fn plli2sq(&self) -> Plli2sqR {
        Plli2sqR::new(((self.bits >> 24) & 0x0f) as u8)
    }
    #[doc = "Bits 28:30 - PLLI2S division factor for I2S clocks"]
    #[inline(always)]
    pub fn plli2sr(&self) -> Plli2srR {
        Plli2srR::new(((self.bits >> 28) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 6:14 - PLLI2S multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plli2sn(&mut self) -> Plli2snW<Plli2scfgrSpec> {
        Plli2snW::new(self, 6)
    }
    #[doc = "Bits 24:27 - PLLI2S division factor for SAI1 clock"]
    #[inline(always)]
    #[must_use]
    pub fn plli2sq(&mut self) -> Plli2sqW<Plli2scfgrSpec> {
        Plli2sqW::new(self, 24)
    }
    #[doc = "Bits 28:30 - PLLI2S division factor for I2S clocks"]
    #[inline(always)]
    #[must_use]
    pub fn plli2sr(&mut self) -> Plli2srW<Plli2scfgrSpec> {
        Plli2srW::new(self, 28)
    }
}
#[doc = "PLLI2S configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`plli2scfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`plli2scfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Plli2scfgrSpec;
impl crate::RegisterSpec for Plli2scfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`plli2scfgr::R`](R) reader structure"]
impl crate::Readable for Plli2scfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`plli2scfgr::W`](W) writer structure"]
impl crate::Writable for Plli2scfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PLLI2SCFGR to value 0x2000_3000"]
impl crate::Resettable for Plli2scfgrSpec {
    const RESET_VALUE: u32 = 0x2000_3000;
}
