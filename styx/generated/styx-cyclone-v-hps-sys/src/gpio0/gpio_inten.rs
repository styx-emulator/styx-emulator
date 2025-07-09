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
#[doc = "Register `gpio_inten` reader"]
pub type R = crate::R<GpioIntenSpec>;
#[doc = "Register `gpio_inten` writer"]
pub type W = crate::W<GpioIntenSpec>;
#[doc = "Allows each bit of Port A Data Register to be configured for interrupt capability. Interrupts are disabled on the corresponding bits of Port A Data Register if the corresponding data direction register is set to Output.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioInten {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<GpioInten> for u32 {
    #[inline(always)]
    fn from(variant: GpioInten) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioInten {
    type Ux = u32;
}
#[doc = "Field `gpio_inten` reader - Allows each bit of Port A Data Register to be configured for interrupt capability. Interrupts are disabled on the corresponding bits of Port A Data Register if the corresponding data direction register is set to Output."]
pub type GpioIntenR = crate::FieldReader<GpioInten>;
impl GpioIntenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioInten> {
        match self.bits {
            0 => Some(GpioInten::Disable),
            1 => Some(GpioInten::Enable),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == GpioInten::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == GpioInten::Enable
    }
}
#[doc = "Field `gpio_inten` writer - Allows each bit of Port A Data Register to be configured for interrupt capability. Interrupts are disabled on the corresponding bits of Port A Data Register if the corresponding data direction register is set to Output."]
pub type GpioIntenW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioInten>;
impl<'a, REG> GpioIntenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(GpioInten::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(GpioInten::Enable)
    }
}
impl R {
    #[doc = "Bits 0:28 - Allows each bit of Port A Data Register to be configured for interrupt capability. Interrupts are disabled on the corresponding bits of Port A Data Register if the corresponding data direction register is set to Output."]
    #[inline(always)]
    pub fn gpio_inten(&self) -> GpioIntenR {
        GpioIntenR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Allows each bit of Port A Data Register to be configured for interrupt capability. Interrupts are disabled on the corresponding bits of Port A Data Register if the corresponding data direction register is set to Output."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_inten(&mut self) -> GpioIntenW<GpioIntenSpec> {
        GpioIntenW::new(self, 0)
    }
}
#[doc = "The Interrupt enable register allows interrupts for each bit of the Port A data register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_inten::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_inten::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioIntenSpec;
impl crate::RegisterSpec for GpioIntenSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`gpio_inten::R`](R) reader structure"]
impl crate::Readable for GpioIntenSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_inten::W`](W) writer structure"]
impl crate::Writable for GpioIntenSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_inten to value 0"]
impl crate::Resettable for GpioIntenSpec {
    const RESET_VALUE: u32 = 0;
}
