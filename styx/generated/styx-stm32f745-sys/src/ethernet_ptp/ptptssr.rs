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
#[doc = "Register `PTPTSSR` reader"]
pub type R = crate::R<PtptssrSpec>;
#[doc = "Register `PTPTSSR` writer"]
pub type W = crate::W<PtptssrSpec>;
#[doc = "Field `TSSO` reader - TSSO"]
pub type TssoR = crate::BitReader;
#[doc = "Field `TSSO` writer - TSSO"]
pub type TssoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSTTR` reader - TSSO"]
pub type TsttrR = crate::BitReader;
#[doc = "Field `TSTTR` writer - TSSO"]
pub type TsttrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TSSO"]
    #[inline(always)]
    pub fn tsso(&self) -> TssoR {
        TssoR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TSSO"]
    #[inline(always)]
    pub fn tsttr(&self) -> TsttrR {
        TsttrR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TSSO"]
    #[inline(always)]
    #[must_use]
    pub fn tsso(&mut self) -> TssoW<PtptssrSpec> {
        TssoW::new(self, 0)
    }
    #[doc = "Bit 1 - TSSO"]
    #[inline(always)]
    #[must_use]
    pub fn tsttr(&mut self) -> TsttrW<PtptssrSpec> {
        TsttrW::new(self, 1)
    }
}
#[doc = "Ethernet PTP time stamp status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptssr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptssrSpec;
impl crate::RegisterSpec for PtptssrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`ptptssr::R`](R) reader structure"]
impl crate::Readable for PtptssrSpec {}
#[doc = "`reset()` method sets PTPTSSR to value 0"]
impl crate::Resettable for PtptssrSpec {
    const RESET_VALUE: u32 = 0;
}
