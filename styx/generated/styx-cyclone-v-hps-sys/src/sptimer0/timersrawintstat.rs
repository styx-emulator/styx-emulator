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
#[doc = "Register `timersrawintstat` reader"]
pub type R = crate::R<TimersrawintstatSpec>;
#[doc = "Register `timersrawintstat` writer"]
pub type W = crate::W<TimersrawintstatSpec>;
#[doc = "Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is before the interrupt mask has been applied. Reading from this register does not clear any active interrupts.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timersrawintstat {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Timersrawintstat> for bool {
    #[inline(always)]
    fn from(variant: Timersrawintstat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timersrawintstat` reader - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is before the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
pub type TimersrawintstatR = crate::BitReader<Timersrawintstat>;
impl TimersrawintstatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timersrawintstat {
        match self.bits {
            false => Timersrawintstat::Inactive,
            true => Timersrawintstat::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Timersrawintstat::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Timersrawintstat::Active
    }
}
#[doc = "Field `timersrawintstat` writer - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is before the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
pub type TimersrawintstatW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is before the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
    #[inline(always)]
    pub fn timersrawintstat(&self) -> TimersrawintstatR {
        TimersrawintstatR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is before the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
    #[inline(always)]
    #[must_use]
    pub fn timersrawintstat(&mut self) -> TimersrawintstatW<TimersrawintstatSpec> {
        TimersrawintstatW::new(self, 0)
    }
}
#[doc = "Provides the interrupt status for all timers before masking. Note that there is only Timer1 in this module instance.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timersrawintstat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimersrawintstatSpec;
impl crate::RegisterSpec for TimersrawintstatSpec {
    type Ux = u32;
    const OFFSET: u64 = 168u64;
}
#[doc = "`read()` method returns [`timersrawintstat::R`](R) reader structure"]
impl crate::Readable for TimersrawintstatSpec {}
#[doc = "`reset()` method sets timersrawintstat to value 0"]
impl crate::Resettable for TimersrawintstatSpec {
    const RESET_VALUE: u32 = 0;
}
