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
#[doc = "Register `msgifgrp_IF1MCTR` reader"]
pub type R = crate::R<MsgifgrpIf1mctrSpec>;
#[doc = "Register `msgifgrp_IF1MCTR` writer"]
pub type W = crate::W<MsgifgrpIf1mctrSpec>;
#[doc = "Field `DLC` reader - 0-8 Data Frame has 0-8 data bytes. 9-15 Data Frame has 8 data bytes. Note: The Data Length Code of a Message Object must be defined the same as in all the corresponding objects with the same identifier at other nodes. When the Message Handler stores a data frame, it will write the DLC to the value given by the received message."]
pub type DlcR = crate::FieldReader;
#[doc = "Field `DLC` writer - 0-8 Data Frame has 0-8 data bytes. 9-15 Data Frame has 8 data bytes. Note: The Data Length Code of a Message Object must be defined the same as in all the corresponding objects with the same identifier at other nodes. When the Message Handler stores a data frame, it will write the DLC to the value given by the received message."]
pub type DlcW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Note: This bit is used to concatenate two or more Message Objects (up to 128) to build a FIFO Buffer. For single Message Objects (not belonging to a FIFO Buffer) this bit must always be set to one.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EoB {
    #[doc = "0: `0`"]
    NotLast = 0,
    #[doc = "1: `1`"]
    SingleOrLast = 1,
}
impl From<EoB> for bool {
    #[inline(always)]
    fn from(variant: EoB) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `EoB` reader - Note: This bit is used to concatenate two or more Message Objects (up to 128) to build a FIFO Buffer. For single Message Objects (not belonging to a FIFO Buffer) this bit must always be set to one."]
pub type EoBR = crate::BitReader<EoB>;
impl EoBR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> EoB {
        match self.bits {
            false => EoB::NotLast,
            true => EoB::SingleOrLast,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_last(&self) -> bool {
        *self == EoB::NotLast
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_single_or_last(&self) -> bool {
        *self == EoB::SingleOrLast
    }
}
#[doc = "Field `EoB` writer - Note: This bit is used to concatenate two or more Message Objects (up to 128) to build a FIFO Buffer. For single Message Objects (not belonging to a FIFO Buffer) this bit must always be set to one."]
pub type EoBW<'a, REG> = crate::BitWriter<'a, REG, EoB>;
impl<'a, REG> EoBW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn not_last(self) -> &'a mut crate::W<REG> {
        self.variant(EoB::NotLast)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn single_or_last(self) -> &'a mut crate::W<REG> {
        self.variant(EoB::SingleOrLast)
    }
}
#[doc = "Transmit Request\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst> for bool {
    #[inline(always)]
    fn from(variant: TxRqst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst` reader - Transmit Request"]
pub type TxRqstR = crate::BitReader<TxRqst>;
impl TxRqstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst {
        match self.bits {
            false => TxRqst::NotWaiting,
            true => TxRqst::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst::Pending
    }
}
#[doc = "Field `TxRqst` writer - Transmit Request"]
pub type TxRqstW<'a, REG> = crate::BitWriter<'a, REG, TxRqst>;
impl<'a, REG> TxRqstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn not_waiting(self) -> &'a mut crate::W<REG> {
        self.variant(TxRqst::NotWaiting)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pending(self) -> &'a mut crate::W<REG> {
        self.variant(TxRqst::Pending)
    }
}
#[doc = "Remote Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RmtEn {
    #[doc = "0: `0`"]
    Unchanged = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<RmtEn> for bool {
    #[inline(always)]
    fn from(variant: RmtEn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `RmtEn` reader - Remote Enable"]
pub type RmtEnR = crate::BitReader<RmtEn>;
impl RmtEnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> RmtEn {
        match self.bits {
            false => RmtEn::Unchanged,
            true => RmtEn::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unchanged(&self) -> bool {
        *self == RmtEn::Unchanged
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == RmtEn::Set
    }
}
#[doc = "Field `RmtEn` writer - Remote Enable"]
pub type RmtEnW<'a, REG> = crate::BitWriter<'a, REG, RmtEn>;
impl<'a, REG> RmtEnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unchanged(self) -> &'a mut crate::W<REG> {
        self.variant(RmtEn::Unchanged)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn set(self) -> &'a mut crate::W<REG> {
        self.variant(RmtEn::Set)
    }
}
#[doc = "Receive Interrupt Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIe {
    #[doc = "0: `0`"]
    Unchanged = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<RxIe> for bool {
    #[inline(always)]
    fn from(variant: RxIe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `RxIE` reader - Receive Interrupt Enable"]
pub type RxIeR = crate::BitReader<RxIe>;
impl RxIeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> RxIe {
        match self.bits {
            false => RxIe::Unchanged,
            true => RxIe::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unchanged(&self) -> bool {
        *self == RxIe::Unchanged
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == RxIe::Set
    }
}
#[doc = "Field `RxIE` writer - Receive Interrupt Enable"]
pub type RxIeW<'a, REG> = crate::BitWriter<'a, REG, RxIe>;
impl<'a, REG> RxIeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unchanged(self) -> &'a mut crate::W<REG> {
        self.variant(RxIe::Unchanged)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn set(self) -> &'a mut crate::W<REG> {
        self.variant(RxIe::Set)
    }
}
#[doc = "Transmit Interrupt Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxIe {
    #[doc = "0: `0`"]
    Unchanged = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<TxIe> for bool {
    #[inline(always)]
    fn from(variant: TxIe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxIE` reader - Transmit Interrupt Enable"]
pub type TxIeR = crate::BitReader<TxIe>;
impl TxIeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxIe {
        match self.bits {
            false => TxIe::Unchanged,
            true => TxIe::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_unchanged(&self) -> bool {
        *self == TxIe::Unchanged
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == TxIe::Set
    }
}
#[doc = "Field `TxIE` writer - Transmit Interrupt Enable"]
pub type TxIeW<'a, REG> = crate::BitWriter<'a, REG, TxIe>;
impl<'a, REG> TxIeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn unchanged(self) -> &'a mut crate::W<REG> {
        self.variant(TxIe::Unchanged)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn set(self) -> &'a mut crate::W<REG> {
        self.variant(TxIe::Set)
    }
}
#[doc = "Use Acceptance Mask\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Umask {
    #[doc = "0: `0`"]
    Ignore = 0,
    #[doc = "1: `1`"]
    Use = 1,
}
impl From<Umask> for bool {
    #[inline(always)]
    fn from(variant: Umask) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `UMask` reader - Use Acceptance Mask"]
pub type UmaskR = crate::BitReader<Umask>;
impl UmaskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Umask {
        match self.bits {
            false => Umask::Ignore,
            true => Umask::Use,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignore(&self) -> bool {
        *self == Umask::Ignore
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_use(&self) -> bool {
        *self == Umask::Use
    }
}
#[doc = "Field `UMask` writer - Use Acceptance Mask"]
pub type UmaskW<'a, REG> = crate::BitWriter<'a, REG, Umask>;
impl<'a, REG> UmaskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ignore(self) -> &'a mut crate::W<REG> {
        self.variant(Umask::Ignore)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn use_(self) -> &'a mut crate::W<REG> {
        self.variant(Umask::Use)
    }
}
#[doc = "Interrupt Pending\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd> for bool {
    #[inline(always)]
    fn from(variant: IntPnd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd` reader - Interrupt Pending"]
pub type IntPndR = crate::BitReader<IntPnd>;
impl IntPndR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd {
        match self.bits {
            false => IntPnd::NotSrc,
            true => IntPnd::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd::Src
    }
}
#[doc = "Field `IntPnd` writer - Interrupt Pending"]
pub type IntPndW<'a, REG> = crate::BitWriter<'a, REG, IntPnd>;
impl<'a, REG> IntPndW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn not_src(self) -> &'a mut crate::W<REG> {
        self.variant(IntPnd::NotSrc)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn src(self) -> &'a mut crate::W<REG> {
        self.variant(IntPnd::Src)
    }
}
#[doc = "Message Lost\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgLst {
    #[doc = "0: `0`"]
    NotLost = 0,
    #[doc = "1: `1`"]
    Lost = 1,
}
impl From<MsgLst> for bool {
    #[inline(always)]
    fn from(variant: MsgLst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgLst` reader - Message Lost"]
pub type MsgLstR = crate::BitReader<MsgLst>;
impl MsgLstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgLst {
        match self.bits {
            false => MsgLst::NotLost,
            true => MsgLst::Lost,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_lost(&self) -> bool {
        *self == MsgLst::NotLost
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_lost(&self) -> bool {
        *self == MsgLst::Lost
    }
}
#[doc = "Field `MsgLst` writer - Message Lost"]
pub type MsgLstW<'a, REG> = crate::BitWriter<'a, REG, MsgLst>;
impl<'a, REG> MsgLstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn not_lost(self) -> &'a mut crate::W<REG> {
        self.variant(MsgLst::NotLost)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn lost(self) -> &'a mut crate::W<REG> {
        self.variant(MsgLst::Lost)
    }
}
#[doc = "New Data\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat> for bool {
    #[inline(always)]
    fn from(variant: NewDat) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat` reader - New Data"]
pub type NewDatR = crate::BitReader<NewDat>;
impl NewDatR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat {
        match self.bits {
            false => NewDat::NotWritten,
            true => NewDat::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat::Written
    }
}
#[doc = "Field `NewDat` writer - New Data"]
pub type NewDatW<'a, REG> = crate::BitWriter<'a, REG, NewDat>;
impl<'a, REG> NewDatW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn not_written(self) -> &'a mut crate::W<REG> {
        self.variant(NewDat::NotWritten)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn written(self) -> &'a mut crate::W<REG> {
        self.variant(NewDat::Written)
    }
}
impl R {
    #[doc = "Bits 0:3 - 0-8 Data Frame has 0-8 data bytes. 9-15 Data Frame has 8 data bytes. Note: The Data Length Code of a Message Object must be defined the same as in all the corresponding objects with the same identifier at other nodes. When the Message Handler stores a data frame, it will write the DLC to the value given by the received message."]
    #[inline(always)]
    pub fn dlc(&self) -> DlcR {
        DlcR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 7 - Note: This bit is used to concatenate two or more Message Objects (up to 128) to build a FIFO Buffer. For single Message Objects (not belonging to a FIFO Buffer) this bit must always be set to one."]
    #[inline(always)]
    pub fn eo_b(&self) -> EoBR {
        EoBR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Transmit Request"]
    #[inline(always)]
    pub fn tx_rqst(&self) -> TxRqstR {
        TxRqstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Remote Enable"]
    #[inline(always)]
    pub fn rmt_en(&self) -> RmtEnR {
        RmtEnR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Receive Interrupt Enable"]
    #[inline(always)]
    pub fn rx_ie(&self) -> RxIeR {
        RxIeR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Transmit Interrupt Enable"]
    #[inline(always)]
    pub fn tx_ie(&self) -> TxIeR {
        TxIeR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Use Acceptance Mask"]
    #[inline(always)]
    pub fn umask(&self) -> UmaskR {
        UmaskR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Interrupt Pending"]
    #[inline(always)]
    pub fn int_pnd(&self) -> IntPndR {
        IntPndR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Message Lost"]
    #[inline(always)]
    pub fn msg_lst(&self) -> MsgLstR {
        MsgLstR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - New Data"]
    #[inline(always)]
    pub fn new_dat(&self) -> NewDatR {
        NewDatR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:3 - 0-8 Data Frame has 0-8 data bytes. 9-15 Data Frame has 8 data bytes. Note: The Data Length Code of a Message Object must be defined the same as in all the corresponding objects with the same identifier at other nodes. When the Message Handler stores a data frame, it will write the DLC to the value given by the received message."]
    #[inline(always)]
    #[must_use]
    pub fn dlc(&mut self) -> DlcW<MsgifgrpIf1mctrSpec> {
        DlcW::new(self, 0)
    }
    #[doc = "Bit 7 - Note: This bit is used to concatenate two or more Message Objects (up to 128) to build a FIFO Buffer. For single Message Objects (not belonging to a FIFO Buffer) this bit must always be set to one."]
    #[inline(always)]
    #[must_use]
    pub fn eo_b(&mut self) -> EoBW<MsgifgrpIf1mctrSpec> {
        EoBW::new(self, 7)
    }
    #[doc = "Bit 8 - Transmit Request"]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst(&mut self) -> TxRqstW<MsgifgrpIf1mctrSpec> {
        TxRqstW::new(self, 8)
    }
    #[doc = "Bit 9 - Remote Enable"]
    #[inline(always)]
    #[must_use]
    pub fn rmt_en(&mut self) -> RmtEnW<MsgifgrpIf1mctrSpec> {
        RmtEnW::new(self, 9)
    }
    #[doc = "Bit 10 - Receive Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn rx_ie(&mut self) -> RxIeW<MsgifgrpIf1mctrSpec> {
        RxIeW::new(self, 10)
    }
    #[doc = "Bit 11 - Transmit Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn tx_ie(&mut self) -> TxIeW<MsgifgrpIf1mctrSpec> {
        TxIeW::new(self, 11)
    }
    #[doc = "Bit 12 - Use Acceptance Mask"]
    #[inline(always)]
    #[must_use]
    pub fn umask(&mut self) -> UmaskW<MsgifgrpIf1mctrSpec> {
        UmaskW::new(self, 12)
    }
    #[doc = "Bit 13 - Interrupt Pending"]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd(&mut self) -> IntPndW<MsgifgrpIf1mctrSpec> {
        IntPndW::new(self, 13)
    }
    #[doc = "Bit 14 - Message Lost"]
    #[inline(always)]
    #[must_use]
    pub fn msg_lst(&mut self) -> MsgLstW<MsgifgrpIf1mctrSpec> {
        MsgLstW::new(self, 14)
    }
    #[doc = "Bit 15 - New Data"]
    #[inline(always)]
    #[must_use]
    pub fn new_dat(&mut self) -> NewDatW<MsgifgrpIf1mctrSpec> {
        NewDatW::new(self, 15)
    }
}
#[doc = "The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1mctr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1mctr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsgifgrpIf1mctrSpec;
impl crate::RegisterSpec for MsgifgrpIf1mctrSpec {
    type Ux = u32;
    const OFFSET: u64 = 268u64;
}
#[doc = "`read()` method returns [`msgifgrp_if1mctr::R`](R) reader structure"]
impl crate::Readable for MsgifgrpIf1mctrSpec {}
#[doc = "`write(|w| ..)` method takes [`msgifgrp_if1mctr::W`](W) writer structure"]
impl crate::Writable for MsgifgrpIf1mctrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets msgifgrp_IF1MCTR to value 0"]
impl crate::Resettable for MsgifgrpIf1mctrSpec {
    const RESET_VALUE: u32 = 0;
}
