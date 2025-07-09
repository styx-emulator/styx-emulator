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
#[doc = "Register `gpio_ver_id_code` reader"]
pub type R = crate::R<GpioVerIdCodeSpec>;
#[doc = "Register `gpio_ver_id_code` writer"]
pub type W = crate::W<GpioVerIdCodeSpec>;
#[doc = "Field `gpio_ver_id_code` reader - ASCII value for each number in the version, followed by *. For example. 32_30_31_2A represents the version 2.01"]
pub type GpioVerIdCodeR = crate::FieldReader<u32>;
#[doc = "Field `gpio_ver_id_code` writer - ASCII value for each number in the version, followed by *. For example. 32_30_31_2A represents the version 2.01"]
pub type GpioVerIdCodeW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - ASCII value for each number in the version, followed by *. For example. 32_30_31_2A represents the version 2.01"]
    #[inline(always)]
    pub fn gpio_ver_id_code(&self) -> GpioVerIdCodeR {
        GpioVerIdCodeR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - ASCII value for each number in the version, followed by *. For example. 32_30_31_2A represents the version 2.01"]
    #[inline(always)]
    #[must_use]
    pub fn gpio_ver_id_code(&mut self) -> GpioVerIdCodeW<GpioVerIdCodeSpec> {
        GpioVerIdCodeW::new(self, 0)
    }
}
#[doc = "GPIO Component Version\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_ver_id_code::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioVerIdCodeSpec;
impl crate::RegisterSpec for GpioVerIdCodeSpec {
    type Ux = u32;
    const OFFSET: u64 = 108u64;
}
#[doc = "`read()` method returns [`gpio_ver_id_code::R`](R) reader structure"]
impl crate::Readable for GpioVerIdCodeSpec {}
#[doc = "`reset()` method sets gpio_ver_id_code to value 0x3230_382a"]
impl crate::Resettable for GpioVerIdCodeSpec {
    const RESET_VALUE: u32 = 0x3230_382a;
}
