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
#[doc = "Register `hostgrp_haintmsk` reader"]
pub type R = crate::R<HostgrpHaintmskSpec>;
#[doc = "Register `hostgrp_haintmsk` writer"]
pub type W = crate::W<HostgrpHaintmskSpec>;
#[doc = "One bit per channel: Bit 0 for channel 0, bit 15 for channel 15\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Haintmsk {
    #[doc = "0: `0`"]
    Mask = 0,
    #[doc = "1: `1`"]
    Nomask = 1,
}
impl From<Haintmsk> for u16 {
    #[inline(always)]
    fn from(variant: Haintmsk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Haintmsk {
    type Ux = u16;
}
#[doc = "Field `haintmsk` reader - One bit per channel: Bit 0 for channel 0, bit 15 for channel 15"]
pub type HaintmskR = crate::FieldReader<Haintmsk>;
impl HaintmskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Haintmsk> {
        match self.bits {
            0 => Some(Haintmsk::Mask),
            1 => Some(Haintmsk::Nomask),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        *self == Haintmsk::Mask
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nomask(&self) -> bool {
        *self == Haintmsk::Nomask
    }
}
#[doc = "Field `haintmsk` writer - One bit per channel: Bit 0 for channel 0, bit 15 for channel 15"]
pub type HaintmskW<'a, REG> = crate::FieldWriter<'a, REG, 16, Haintmsk>;
impl<'a, REG> HaintmskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u16>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mask(self) -> &'a mut crate::W<REG> {
        self.variant(Haintmsk::Mask)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nomask(self) -> &'a mut crate::W<REG> {
        self.variant(Haintmsk::Nomask)
    }
}
impl R {
    #[doc = "Bits 0:15 - One bit per channel: Bit 0 for channel 0, bit 15 for channel 15"]
    #[inline(always)]
    pub fn haintmsk(&self) -> HaintmskR {
        HaintmskR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - One bit per channel: Bit 0 for channel 0, bit 15 for channel 15"]
    #[inline(always)]
    #[must_use]
    pub fn haintmsk(&mut self) -> HaintmskW<HostgrpHaintmskSpec> {
        HaintmskW::new(self, 0)
    }
}
#[doc = "The Host All Channel Interrupt Mask register works with the Host All Channel Interrupt register to interrupt the application when an event occurs on a channel. There is one interrupt mask bit per channel, up to a maximum of 16 bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_haintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_haintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHaintmskSpec;
impl crate::RegisterSpec for HostgrpHaintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 1048u64;
}
#[doc = "`read()` method returns [`hostgrp_haintmsk::R`](R) reader structure"]
impl crate::Readable for HostgrpHaintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_haintmsk::W`](W) writer structure"]
impl crate::Writable for HostgrpHaintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_haintmsk to value 0"]
impl crate::Resettable for HostgrpHaintmskSpec {
    const RESET_VALUE: u32 = 0;
}
