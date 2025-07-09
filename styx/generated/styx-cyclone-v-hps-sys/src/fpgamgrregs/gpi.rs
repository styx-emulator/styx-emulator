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
#[doc = "Register `gpi` reader"]
pub type R = crate::R<GpiSpec>;
#[doc = "Register `gpi` writer"]
pub type W = crate::W<GpiSpec>;
#[doc = "Field `value` reader - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<GpiSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Provides a low-latency, low-performance, and simple way to read general-purpose signals driven from the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpiSpec;
impl crate::RegisterSpec for GpiSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`gpi::R`](R) reader structure"]
impl crate::Readable for GpiSpec {}
