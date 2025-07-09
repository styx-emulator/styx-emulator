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
#[doc = "Register `gpio_debounce` reader"]
pub type R = crate::R<GpioDebounceSpec>;
#[doc = "Register `gpio_debounce` writer"]
pub type W = crate::W<GpioDebounceSpec>;
#[doc = "Controls whether an external signal that is the source of an interrupt needs to be debounced to remove any spurious glitches. A signal must be valid for two periods of an external clock (gpio_db_clk) before it is internally processed.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioDebounce {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<GpioDebounce> for u32 {
    #[inline(always)]
    fn from(variant: GpioDebounce) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioDebounce {
    type Ux = u32;
}
#[doc = "Field `gpio_debounce` reader - Controls whether an external signal that is the source of an interrupt needs to be debounced to remove any spurious glitches. A signal must be valid for two periods of an external clock (gpio_db_clk) before it is internally processed."]
pub type GpioDebounceR = crate::FieldReader<GpioDebounce>;
impl GpioDebounceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioDebounce> {
        match self.bits {
            0 => Some(GpioDebounce::Disable),
            1 => Some(GpioDebounce::Enable),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == GpioDebounce::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == GpioDebounce::Enable
    }
}
#[doc = "Field `gpio_debounce` writer - Controls whether an external signal that is the source of an interrupt needs to be debounced to remove any spurious glitches. A signal must be valid for two periods of an external clock (gpio_db_clk) before it is internally processed."]
pub type GpioDebounceW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioDebounce>;
impl<'a, REG> GpioDebounceW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(GpioDebounce::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(GpioDebounce::Enable)
    }
}
impl R {
    #[doc = "Bits 0:28 - Controls whether an external signal that is the source of an interrupt needs to be debounced to remove any spurious glitches. A signal must be valid for two periods of an external clock (gpio_db_clk) before it is internally processed."]
    #[inline(always)]
    pub fn gpio_debounce(&self) -> GpioDebounceR {
        GpioDebounceR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Controls whether an external signal that is the source of an interrupt needs to be debounced to remove any spurious glitches. A signal must be valid for two periods of an external clock (gpio_db_clk) before it is internally processed."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_debounce(&mut self) -> GpioDebounceW<GpioDebounceSpec> {
        GpioDebounceW::new(self, 0)
    }
}
#[doc = "Debounces each IO Pin\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_debounce::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_debounce::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioDebounceSpec;
impl crate::RegisterSpec for GpioDebounceSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`gpio_debounce::R`](R) reader structure"]
impl crate::Readable for GpioDebounceSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_debounce::W`](W) writer structure"]
impl crate::Writable for GpioDebounceSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_debounce to value 0"]
impl crate::Resettable for GpioDebounceSpec {
    const RESET_VALUE: u32 = 0;
}
