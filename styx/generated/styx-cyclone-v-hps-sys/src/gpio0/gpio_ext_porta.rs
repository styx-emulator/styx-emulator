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
#[doc = "Register `gpio_ext_porta` reader"]
pub type R = crate::R<GpioExtPortaSpec>;
#[doc = "Register `gpio_ext_porta` writer"]
pub type W = crate::W<GpioExtPortaSpec>;
#[doc = "Field `gpio_ext_porta` reader - When Port A Data Register is configured as Input, then reading this location reads the values on the signals. When the data direction of Port A Data Register is set as Output, reading this location reads Port A Data Register"]
pub type GpioExtPortaR = crate::FieldReader<u32>;
#[doc = "Field `gpio_ext_porta` writer - When Port A Data Register is configured as Input, then reading this location reads the values on the signals. When the data direction of Port A Data Register is set as Output, reading this location reads Port A Data Register"]
pub type GpioExtPortaW<'a, REG> = crate::FieldWriter<'a, REG, 29, u32>;
impl R {
    #[doc = "Bits 0:28 - When Port A Data Register is configured as Input, then reading this location reads the values on the signals. When the data direction of Port A Data Register is set as Output, reading this location reads Port A Data Register"]
    #[inline(always)]
    pub fn gpio_ext_porta(&self) -> GpioExtPortaR {
        GpioExtPortaR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - When Port A Data Register is configured as Input, then reading this location reads the values on the signals. When the data direction of Port A Data Register is set as Output, reading this location reads Port A Data Register"]
    #[inline(always)]
    #[must_use]
    pub fn gpio_ext_porta(&mut self) -> GpioExtPortaW<GpioExtPortaSpec> {
        GpioExtPortaW::new(self, 0)
    }
}
#[doc = "The external port register is used to input data to the metastability flops.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_ext_porta::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioExtPortaSpec;
impl crate::RegisterSpec for GpioExtPortaSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`gpio_ext_porta::R`](R) reader structure"]
impl crate::Readable for GpioExtPortaSpec {}
#[doc = "`reset()` method sets gpio_ext_porta to value 0"]
impl crate::Resettable for GpioExtPortaSpec {
    const RESET_VALUE: u32 = 0;
}
