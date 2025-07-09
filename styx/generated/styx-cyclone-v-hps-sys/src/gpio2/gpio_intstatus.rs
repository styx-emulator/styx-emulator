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
#[doc = "Register `gpio_intstatus` reader"]
pub type R = crate::R<GpioIntstatusSpec>;
#[doc = "Register `gpio_intstatus` writer"]
pub type W = crate::W<GpioIntstatusSpec>;
#[doc = "Interrupt status of Port A Data Register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GpioIntstatus {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<GpioIntstatus> for u32 {
    #[inline(always)]
    fn from(variant: GpioIntstatus) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for GpioIntstatus {
    type Ux = u32;
}
#[doc = "Field `gpio_intstatus` reader - Interrupt status of Port A Data Register."]
pub type GpioIntstatusR = crate::FieldReader<GpioIntstatus>;
impl GpioIntstatusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<GpioIntstatus> {
        match self.bits {
            0 => Some(GpioIntstatus::Inactive),
            1 => Some(GpioIntstatus::Active),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == GpioIntstatus::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == GpioIntstatus::Active
    }
}
#[doc = "Field `gpio_intstatus` writer - Interrupt status of Port A Data Register."]
pub type GpioIntstatusW<'a, REG> = crate::FieldWriter<'a, REG, 29, GpioIntstatus>;
impl<'a, REG> GpioIntstatusW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(GpioIntstatus::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(GpioIntstatus::Active)
    }
}
impl R {
    #[doc = "Bits 0:28 - Interrupt status of Port A Data Register."]
    #[inline(always)]
    pub fn gpio_intstatus(&self) -> GpioIntstatusR {
        GpioIntstatusR::new(self.bits & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:28 - Interrupt status of Port A Data Register."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_intstatus(&mut self) -> GpioIntstatusW<GpioIntstatusSpec> {
        GpioIntstatusW::new(self, 0)
    }
}
#[doc = "The Interrupt status is reported for all Port A Data Register Bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_intstatus::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_intstatus::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioIntstatusSpec;
impl crate::RegisterSpec for GpioIntstatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`gpio_intstatus::R`](R) reader structure"]
impl crate::Readable for GpioIntstatusSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_intstatus::W`](W) writer structure"]
impl crate::Writable for GpioIntstatusSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_intstatus to value 0"]
impl crate::Resettable for GpioIntstatusSpec {
    const RESET_VALUE: u32 = 0;
}
