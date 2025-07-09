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
#[doc = "Register `timer1intstat` reader"]
pub type R = crate::R<Timer1intstatSpec>;
#[doc = "Register `timer1intstat` writer"]
pub type W = crate::W<Timer1intstatSpec>;
#[doc = "Provides the interrupt status for Timer1. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer1intstat {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Timer1intstat> for bool {
    #[inline(always)]
    fn from(variant: Timer1intstat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timer1intstat` reader - Provides the interrupt status for Timer1. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
pub type Timer1intstatR = crate::BitReader<Timer1intstat>;
impl Timer1intstatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timer1intstat {
        match self.bits {
            false => Timer1intstat::Inactive,
            true => Timer1intstat::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Timer1intstat::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Timer1intstat::Active
    }
}
#[doc = "Field `timer1intstat` writer - Provides the interrupt status for Timer1. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
pub type Timer1intstatW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Provides the interrupt status for Timer1. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
    #[inline(always)]
    pub fn timer1intstat(&self) -> Timer1intstatR {
        Timer1intstatR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Provides the interrupt status for Timer1. The status reported is after the interrupt mask has been applied. Reading from this register does not clear any active interrupts."]
    #[inline(always)]
    #[must_use]
    pub fn timer1intstat(&mut self) -> Timer1intstatW<Timer1intstatSpec> {
        Timer1intstatW::new(self, 0)
    }
}
#[doc = "Provides the interrupt status of Timer1 after masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1intstat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Timer1intstatSpec;
impl crate::RegisterSpec for Timer1intstatSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`timer1intstat::R`](R) reader structure"]
impl crate::Readable for Timer1intstatSpec {}
#[doc = "`reset()` method sets timer1intstat to value 0"]
impl crate::Resettable for Timer1intstatSpec {
    const RESET_VALUE: u32 = 0;
}
