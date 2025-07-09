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
#[doc = "Register `timersintstat` reader"]
pub type R = crate::R<TimersintstatSpec>;
#[doc = "Register `timersintstat` writer"]
pub type W = crate::W<TimersintstatSpec>;
#[doc = "Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timersintstat {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Timersintstat> for bool {
    #[inline(always)]
    fn from(variant: Timersintstat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timersintstat` reader - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
pub type TimersintstatR = crate::BitReader<Timersintstat>;
impl TimersintstatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timersintstat {
        match self.bits {
            false => Timersintstat::Inactive,
            true => Timersintstat::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Timersintstat::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Timersintstat::Active
    }
}
#[doc = "Field `timersintstat` writer - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
pub type TimersintstatW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
    #[inline(always)]
    pub fn timersintstat(&self) -> TimersintstatR {
        TimersintstatR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Provides the interrupt status for Timer1. Because there is only Timer1 in this module instance, this status is the same as timer1intstat. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
    #[inline(always)]
    #[must_use]
    pub fn timersintstat(&mut self) -> TimersintstatW<TimersintstatSpec> {
        TimersintstatW::new(self, 0)
    }
}
#[doc = "Provides the interrupt status for all timers after masking. Because there is only Timer1 in this module instance, this status is the same as timer1intstat.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timersintstat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimersintstatSpec;
impl crate::RegisterSpec for TimersintstatSpec {
    type Ux = u32;
    const OFFSET: u64 = 160u64;
}
#[doc = "`read()` method returns [`timersintstat::R`](R) reader structure"]
impl crate::Readable for TimersintstatSpec {}
#[doc = "`reset()` method sets timersintstat to value 0"]
impl crate::Resettable for TimersintstatSpec {
    const RESET_VALUE: u32 = 0;
}
