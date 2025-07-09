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
#[doc = "Register `hostgrp_hfnum` reader"]
pub type R = crate::R<HostgrpHfnumSpec>;
#[doc = "Register `hostgrp_hfnum` writer"]
pub type W = crate::W<HostgrpHfnumSpec>;
#[doc = "This field increments when a new SOF is transmitted on the USB, and is reset to 0 when it reaches 0x3FFF. Reads Return the Frame number value.\n\nValue on reset: 16383"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Frnum {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Frnum> for u16 {
    #[inline(always)]
    fn from(variant: Frnum) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Frnum {
    type Ux = u16;
}
#[doc = "Field `frnum` reader - This field increments when a new SOF is transmitted on the USB, and is reset to 0 when it reaches 0x3FFF. Reads Return the Frame number value."]
pub type FrnumR = crate::FieldReader<Frnum>;
impl FrnumR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Frnum> {
        match self.bits {
            0 => Some(Frnum::Inactive),
            1 => Some(Frnum::Active),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Frnum::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Frnum::Active
    }
}
#[doc = "Field `frnum` writer - This field increments when a new SOF is transmitted on the USB, and is reset to 0 when it reaches 0x3FFF. Reads Return the Frame number value."]
pub type FrnumW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `frrem` reader - Indicates the amount of time remaining in the current microframe (HS) or Frame (FS/LS), in terms of PHY clocks. This field decrements on each PHY clock. When it reaches zero, this field is reloaded with the value in the Frame Interval register and a new SOF is transmitted on the USB."]
pub type FrremR = crate::FieldReader<u16>;
#[doc = "Field `frrem` writer - Indicates the amount of time remaining in the current microframe (HS) or Frame (FS/LS), in terms of PHY clocks. This field decrements on each PHY clock. When it reaches zero, this field is reloaded with the value in the Frame Interval register and a new SOF is transmitted on the USB."]
pub type FrremW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This field increments when a new SOF is transmitted on the USB, and is reset to 0 when it reaches 0x3FFF. Reads Return the Frame number value."]
    #[inline(always)]
    pub fn frnum(&self) -> FrnumR {
        FrnumR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - Indicates the amount of time remaining in the current microframe (HS) or Frame (FS/LS), in terms of PHY clocks. This field decrements on each PHY clock. When it reaches zero, this field is reloaded with the value in the Frame Interval register and a new SOF is transmitted on the USB."]
    #[inline(always)]
    pub fn frrem(&self) -> FrremR {
        FrremR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field increments when a new SOF is transmitted on the USB, and is reset to 0 when it reaches 0x3FFF. Reads Return the Frame number value."]
    #[inline(always)]
    #[must_use]
    pub fn frnum(&mut self) -> FrnumW<HostgrpHfnumSpec> {
        FrnumW::new(self, 0)
    }
    #[doc = "Bits 16:31 - Indicates the amount of time remaining in the current microframe (HS) or Frame (FS/LS), in terms of PHY clocks. This field decrements on each PHY clock. When it reaches zero, this field is reloaded with the value in the Frame Interval register and a new SOF is transmitted on the USB."]
    #[inline(always)]
    #[must_use]
    pub fn frrem(&mut self) -> FrremW<HostgrpHfnumSpec> {
        FrremW::new(self, 16)
    }
}
#[doc = "This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hfnum::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHfnumSpec;
impl crate::RegisterSpec for HostgrpHfnumSpec {
    type Ux = u32;
    const OFFSET: u64 = 1032u64;
}
#[doc = "`read()` method returns [`hostgrp_hfnum::R`](R) reader structure"]
impl crate::Readable for HostgrpHfnumSpec {}
#[doc = "`reset()` method sets hostgrp_hfnum to value 0x3fff"]
impl crate::Resettable for HostgrpHfnumSpec {
    const RESET_VALUE: u32 = 0x3fff;
}
