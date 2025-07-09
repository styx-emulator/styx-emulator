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
#[doc = "Register `protogrp_HWS` reader"]
pub type R = crate::R<ProtogrpHwsSpec>;
#[doc = "Register `protogrp_HWS` writer"]
pub type W = crate::W<ProtogrpHwsSpec>;
#[doc = "Message Buffer Count\n\nValue on reset: 3"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MbW {
    #[doc = "0: `0`"]
    MsgObjs16 = 0,
    #[doc = "1: `1`"]
    MsgObjs32 = 1,
    #[doc = "2: `10`"]
    MsgObjs64 = 2,
    #[doc = "3: `11`"]
    MsgObjs128 = 3,
}
impl From<MbW> for u8 {
    #[inline(always)]
    fn from(variant: MbW) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for MbW {
    type Ux = u8;
}
#[doc = "Field `mb_w` reader - Message Buffer Count"]
pub type MbWR = crate::FieldReader<MbW>;
impl MbWR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MbW {
        match self.bits {
            0 => MbW::MsgObjs16,
            1 => MbW::MsgObjs32,
            2 => MbW::MsgObjs64,
            3 => MbW::MsgObjs128,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_msg_objs16(&self) -> bool {
        *self == MbW::MsgObjs16
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_msg_objs32(&self) -> bool {
        *self == MbW::MsgObjs32
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_msg_objs64(&self) -> bool {
        *self == MbW::MsgObjs64
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_msg_objs128(&self) -> bool {
        *self == MbW::MsgObjs128
    }
}
#[doc = "Field `mb_w` writer - Message Buffer Count"]
pub type MbWW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Parity Generation\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paren {
    #[doc = "0: `0`"]
    NotPresent = 0,
    #[doc = "1: `1`"]
    Present = 1,
}
impl From<Paren> for bool {
    #[inline(always)]
    fn from(variant: Paren) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `paren` reader - Parity Generation"]
pub type ParenR = crate::BitReader<Paren>;
impl ParenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Paren {
        match self.bits {
            false => Paren::NotPresent,
            true => Paren::Present,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_present(&self) -> bool {
        *self == Paren::NotPresent
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_present(&self) -> bool {
        *self == Paren::Present
    }
}
#[doc = "Field `paren` writer - Parity Generation"]
pub type ParenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - Message Buffer Count"]
    #[inline(always)]
    pub fn mb_w(&self) -> MbWR {
        MbWR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - Parity Generation"]
    #[inline(always)]
    pub fn paren(&self) -> ParenR {
        ParenR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - Message Buffer Count"]
    #[inline(always)]
    #[must_use]
    pub fn mb_w(&mut self) -> MbWW<ProtogrpHwsSpec> {
        MbWW::new(self, 0)
    }
    #[doc = "Bit 2 - Parity Generation"]
    #[inline(always)]
    #[must_use]
    pub fn paren(&mut self) -> ParenW<ProtogrpHwsSpec> {
        ParenW::new(self, 2)
    }
}
#[doc = "Hardware Configuration Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_hws::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpHwsSpec;
impl crate::RegisterSpec for ProtogrpHwsSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`protogrp_hws::R`](R) reader structure"]
impl crate::Readable for ProtogrpHwsSpec {}
#[doc = "`reset()` method sets protogrp_HWS to value 0x03"]
impl crate::Resettable for ProtogrpHwsSpec {
    const RESET_VALUE: u32 = 0x03;
}
