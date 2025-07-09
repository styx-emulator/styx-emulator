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
#[doc = "Register `gpio_intmask` reader"]
pub type R = crate::R<GpioIntmaskSpec>;
#[doc = "Register `gpio_intmask` writer"]
pub type W = crate::W<GpioIntmaskSpec>;
#[doc = "Controls whether an interrupt on Port A Data Register can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioIntmask {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<GpioIntmask> for u32 {
    #[inline(always)]
    fn from(variant: GpioIntmask) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioIntmask {
    type Ux = u32;
}
#[doc = "Field `gpio_intmask` reader - Controls whether an interrupt on Port A Data Register can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type GpioIntmaskR = crate::FieldReader<GpioIntmask>;
impl GpioIntmaskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioIntmask> {
        match self.bits {
            0 => Some(GpioIntmask::Disable),
            1 => Some(GpioIntmask::Enable),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == GpioIntmask::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == GpioIntmask::Enable
    }
}
#[doc = "Field `gpio_intmask` writer - Controls whether an interrupt on Port A Data Register can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
pub type GpioIntmaskW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioIntmask>;
impl<'a, REG> GpioIntmaskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(GpioIntmask::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(GpioIntmask::Enable)
    }
}
impl R {
    #[doc = "Bits 0:28 - Controls whether an interrupt on Port A Data Register can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    pub fn gpio_intmask(&self) -> GpioIntmaskR {
        GpioIntmaskR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Controls whether an interrupt on Port A Data Register can generate an interrupt to the interrupt controller by not masking it. The unmasked status can be read as well as the resultant status after masking."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_intmask(&mut self) -> GpioIntmaskW<GpioIntmaskSpec> {
        GpioIntmaskW::new(self, 0)
    }
}
#[doc = "Controls which pins cause interrupts on Port A Data Register inputs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_intmask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_intmask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioIntmaskSpec;
impl crate::RegisterSpec for GpioIntmaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`gpio_intmask::R`](R) reader structure"]
impl crate::Readable for GpioIntmaskSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_intmask::W`](W) writer structure"]
impl crate::Writable for GpioIntmaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_intmask to value 0"]
impl crate::Resettable for GpioIntmaskSpec {
    const RESET_VALUE: u32 = 0;
}
