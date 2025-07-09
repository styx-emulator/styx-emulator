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
#[doc = "Register `gpio_porta_eoi` reader"]
pub type R = crate::R<GpioPortaEoiSpec>;
#[doc = "Register `gpio_porta_eoi` writer"]
pub type W = crate::W<GpioPortaEoiSpec>;
#[doc = "Field `gpio_porta_eoi` reader - Controls the clearing of edge type interrupts from the Port A Data Register."]
pub type GpioPortaEoiR = crate::FieldReader<u32>;
#[doc = "Controls the clearing of edge type interrupts from the Port A Data Register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioPortaEoi {
    #[doc = "0: `0`"]
    Noclr = 0,
    #[doc = "1: `1`"]
    Clr = 1,
}
impl From<GpioPortaEoi> for u32 {
    #[inline(always)]
    fn from(variant: GpioPortaEoi) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioPortaEoi {
    type Ux = u32;
}
#[doc = "Field `gpio_porta_eoi` writer - Controls the clearing of edge type interrupts from the Port A Data Register."]
pub type GpioPortaEoiW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioPortaEoi>;
impl<'a, REG> GpioPortaEoiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclr(self) -> &'a mut crate::W<REG> {
        self.variant(GpioPortaEoi::Noclr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clr(self) -> &'a mut crate::W<REG> {
        self.variant(GpioPortaEoi::Clr)
    }
}
impl R {
    #[doc = "Bits 0:28 - Controls the clearing of edge type interrupts from the Port A Data Register."]
    #[inline(always)]
    pub fn gpio_porta_eoi(&self) -> GpioPortaEoiR {
        GpioPortaEoiR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Controls the clearing of edge type interrupts from the Port A Data Register."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_porta_eoi(&mut self) -> GpioPortaEoiW<GpioPortaEoiSpec> {
        GpioPortaEoiW::new(self, 0)
    }
}
#[doc = "Port A Data Register interrupt handling.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_porta_eoi::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioPortaEoiSpec;
impl crate::RegisterSpec for GpioPortaEoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`write(|w| ..)` method takes [`gpio_porta_eoi::W`](W) writer structure"]
impl crate::Writable for GpioPortaEoiSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_porta_eoi to value 0"]
impl crate::Resettable for GpioPortaEoiSpec {
    const RESET_VALUE: u32 = 0;
}
