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
#[doc = "Register `gpio_swporta_dr` reader"]
pub type R = crate::R<GpioSwportaDrSpec>;
#[doc = "Register `gpio_swporta_dr` writer"]
pub type W = crate::W<GpioSwportaDrSpec>;
#[doc = "Field `gpio_swporta_dr` reader - Values written to this register are output on the I/O signals of the GPIO Data Register, if the corresponding data direction bits for GPIO Data Direction Field are set to Output mode. The value read back is equal to the last value written to this register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
pub type GpioSwportaDrR = crate::FieldReader<u32>;
#[doc = "Field `gpio_swporta_dr` writer - Values written to this register are output on the I/O signals of the GPIO Data Register, if the corresponding data direction bits for GPIO Data Direction Field are set to Output mode. The value read back is equal to the last value written to this register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
pub type GpioSwportaDrW<'a, REG> = crate::FieldWriter<'a, REG, 29, u32>;
impl R {
    #[doc = "Bits 0:28 - Values written to this register are output on the I/O signals of the GPIO Data Register, if the corresponding data direction bits for GPIO Data Direction Field are set to Output mode. The value read back is equal to the last value written to this register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
    #[inline(always)]
    pub fn gpio_swporta_dr(&self) -> GpioSwportaDrR {
        GpioSwportaDrR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Values written to this register are output on the I/O signals of the GPIO Data Register, if the corresponding data direction bits for GPIO Data Direction Field are set to Output mode. The value read back is equal to the last value written to this register. Check the GPIO chapter in the handbook for details on how GPIO2 is implemented."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_swporta_dr(&mut self) -> GpioSwportaDrW<GpioSwportaDrSpec> {
        GpioSwportaDrW::new(self, 0)
    }
}
#[doc = "This GPIO Data register is used to input or output data Check the GPIO chapter in the handbook for details on how GPIO2 is implemented.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_swporta_dr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_swporta_dr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioSwportaDrSpec;
impl crate::RegisterSpec for GpioSwportaDrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`gpio_swporta_dr::R`](R) reader structure"]
impl crate::Readable for GpioSwportaDrSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_swporta_dr::W`](W) writer structure"]
impl crate::Writable for GpioSwportaDrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_swporta_dr to value 0"]
impl crate::Resettable for GpioSwportaDrSpec {
    const RESET_VALUE: u32 = 0;
}
