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
#[doc = "Register `msgifgrp_IF2ARB` reader"]
pub type R = crate::R<MsgifgrpIf2arbSpec>;
#[doc = "Register `msgifgrp_IF2ARB` writer"]
pub type W = crate::W<MsgifgrpIf2arbSpec>;
#[doc = "Field `ID` reader - ID28 - ID0 29-bit Identifier (Extended Frame). ID28 - ID18 11-bit Identifier (Standard Frame)."]
pub type IdR = crate::FieldReader<u32>;
#[doc = "Field `ID` writer - ID28 - ID0 29-bit Identifier (Extended Frame). ID28 - ID18 11-bit Identifier (Standard Frame)."]
pub type IdW<'a, REG> = crate::FieldWriter<'a, REG, 29, u32>;
#[doc = "Message Direction\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    #[doc = "0: `0`"]
    Rx = 0,
    #[doc = "1: `1`"]
    Tx = 1,
}
impl From<Dir> for bool {
    #[inline(always)]
    fn from(variant: Dir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Dir` reader - Message Direction"]
pub type DirR = crate::BitReader<Dir>;
impl DirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dir {
        match self.bits {
            false => Dir::Rx,
            true => Dir::Tx,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rx(&self) -> bool {
        *self == Dir::Rx
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_tx(&self) -> bool {
        *self == Dir::Tx
    }
}
#[doc = "Field `Dir` writer - Message Direction"]
pub type DirW<'a, REG> = crate::BitWriter<'a, REG, Dir>;
impl<'a, REG> DirW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rx(self) -> &'a mut crate::W<REG> {
        self.variant(Dir::Rx)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn tx(self) -> &'a mut crate::W<REG> {
        self.variant(Dir::Tx)
    }
}
#[doc = "Extended Identifier\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xtd {
    #[doc = "0: `0`"]
    Standard = 0,
    #[doc = "1: `1`"]
    Extended = 1,
}
impl From<Xtd> for bool {
    #[inline(always)]
    fn from(variant: Xtd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Xtd` reader - Extended Identifier"]
pub type XtdR = crate::BitReader<Xtd>;
impl XtdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xtd {
        match self.bits {
            false => Xtd::Standard,
            true => Xtd::Extended,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_standard(&self) -> bool {
        *self == Xtd::Standard
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_extended(&self) -> bool {
        *self == Xtd::Extended
    }
}
#[doc = "Field `Xtd` writer - Extended Identifier"]
pub type XtdW<'a, REG> = crate::BitWriter<'a, REG, Xtd>;
impl<'a, REG> XtdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn standard(self) -> &'a mut crate::W<REG> {
        self.variant(Xtd::Standard)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn extended(self) -> &'a mut crate::W<REG> {
        self.variant(Xtd::Extended)
    }
}
#[doc = "The CPU must reset the MsgVal bit of all unused Messages Objects during the initialization before it resets bit Init in the CAN Control Register. MsgVal must also be reset if the Messages Object is no longer used in operation. For reconfiguration of Message Objects during normal operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal> for bool {
    #[inline(always)]
    fn from(variant: MsgVal) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal` reader - The CPU must reset the MsgVal bit of all unused Messages Objects during the initialization before it resets bit Init in the CAN Control Register. MsgVal must also be reset if the Messages Object is no longer used in operation. For reconfiguration of Message Objects during normal operation."]
pub type MsgValR = crate::BitReader<MsgVal>;
impl MsgValR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal {
        match self.bits {
            false => MsgVal::Ignored,
            true => MsgVal::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal::Considered
    }
}
#[doc = "Field `MsgVal` writer - The CPU must reset the MsgVal bit of all unused Messages Objects during the initialization before it resets bit Init in the CAN Control Register. MsgVal must also be reset if the Messages Object is no longer used in operation. For reconfiguration of Message Objects during normal operation."]
pub type MsgValW<'a, REG> = crate::BitWriter<'a, REG, MsgVal>;
impl<'a, REG> MsgValW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ignored(self) -> &'a mut crate::W<REG> {
        self.variant(MsgVal::Ignored)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn considered(self) -> &'a mut crate::W<REG> {
        self.variant(MsgVal::Considered)
    }
}
impl R {
    #[doc = "Bits 0:28 - ID28 - ID0 29-bit Identifier (Extended Frame). ID28 - ID18 11-bit Identifier (Standard Frame)."]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(self.bits & 0x1fff_ffff)
    }
    #[doc = "Bit 29 - Message Direction"]
    #[inline(always)]
    pub fn dir(&self) -> DirR {
        DirR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Extended Identifier"]
    #[inline(always)]
    pub fn xtd(&self) -> XtdR {
        XtdR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - The CPU must reset the MsgVal bit of all unused Messages Objects during the initialization before it resets bit Init in the CAN Control Register. MsgVal must also be reset if the Messages Object is no longer used in operation. For reconfiguration of Message Objects during normal operation."]
    #[inline(always)]
    pub fn msg_val(&self) -> MsgValR {
        MsgValR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:28 - ID28 - ID0 29-bit Identifier (Extended Frame). ID28 - ID18 11-bit Identifier (Standard Frame)."]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<MsgifgrpIf2arbSpec> {
        IdW::new(self, 0)
    }
    #[doc = "Bit 29 - Message Direction"]
    #[inline(always)]
    #[must_use]
    pub fn dir(&mut self) -> DirW<MsgifgrpIf2arbSpec> {
        DirW::new(self, 29)
    }
    #[doc = "Bit 30 - Extended Identifier"]
    #[inline(always)]
    #[must_use]
    pub fn xtd(&mut self) -> XtdW<MsgifgrpIf2arbSpec> {
        XtdW::new(self, 30)
    }
    #[doc = "Bit 31 - The CPU must reset the MsgVal bit of all unused Messages Objects during the initialization before it resets bit Init in the CAN Control Register. MsgVal must also be reset if the Messages Object is no longer used in operation. For reconfiguration of Message Objects during normal operation."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val(&mut self) -> MsgValW<MsgifgrpIf2arbSpec> {
        MsgValW::new(self, 31)
    }
}
#[doc = "The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2arb::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2arb::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsgifgrpIf2arbSpec;
impl crate::RegisterSpec for MsgifgrpIf2arbSpec {
    type Ux = u32;
    const OFFSET: u64 = 296u64;
}
#[doc = "`read()` method returns [`msgifgrp_if2arb::R`](R) reader structure"]
impl crate::Readable for MsgifgrpIf2arbSpec {}
#[doc = "`write(|w| ..)` method takes [`msgifgrp_if2arb::W`](W) writer structure"]
impl crate::Writable for MsgifgrpIf2arbSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets msgifgrp_IF2ARB to value 0"]
impl crate::Resettable for MsgifgrpIf2arbSpec {
    const RESET_VALUE: u32 = 0;
}
