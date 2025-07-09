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
#[doc = "Register `cmd` reader"]
pub type R = crate::R<CmdSpec>;
#[doc = "Register `cmd` writer"]
pub type W = crate::W<CmdSpec>;
#[doc = "Field `cmd_index` reader - Tracks the command index number. Values from 0-31."]
pub type CmdIndexR = crate::FieldReader;
#[doc = "Field `cmd_index` writer - Tracks the command index number. Values from 0-31."]
pub type CmdIndexW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Response expected from card.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseExpect {
    #[doc = "0: `0`"]
    Resp = 0,
    #[doc = "1: `1`"]
    Noresp = 1,
}
impl From<ResponseExpect> for bool {
    #[inline(always)]
    fn from(variant: ResponseExpect) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `response_expect` reader - Response expected from card."]
pub type ResponseExpectR = crate::BitReader<ResponseExpect>;
impl ResponseExpectR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ResponseExpect {
        match self.bits {
            false => ResponseExpect::Resp,
            true => ResponseExpect::Noresp,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_resp(&self) -> bool {
        *self == ResponseExpect::Resp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_noresp(&self) -> bool {
        *self == ResponseExpect::Noresp
    }
}
#[doc = "Field `response_expect` writer - Response expected from card."]
pub type ResponseExpectW<'a, REG> = crate::BitWriter<'a, REG, ResponseExpect>;
impl<'a, REG> ResponseExpectW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn resp(self) -> &'a mut crate::W<REG> {
        self.variant(ResponseExpect::Resp)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn noresp(self) -> &'a mut crate::W<REG> {
        self.variant(ResponseExpect::Noresp)
    }
}
#[doc = "Provides long and short response\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseLength {
    #[doc = "0: `0`"]
    Short = 0,
    #[doc = "1: `1`"]
    Long = 1,
}
impl From<ResponseLength> for bool {
    #[inline(always)]
    fn from(variant: ResponseLength) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `response_length` reader - Provides long and short response"]
pub type ResponseLengthR = crate::BitReader<ResponseLength>;
impl ResponseLengthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ResponseLength {
        match self.bits {
            false => ResponseLength::Short,
            true => ResponseLength::Long,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_short(&self) -> bool {
        *self == ResponseLength::Short
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_long(&self) -> bool {
        *self == ResponseLength::Long
    }
}
#[doc = "Field `response_length` writer - Provides long and short response"]
pub type ResponseLengthW<'a, REG> = crate::BitWriter<'a, REG, ResponseLength>;
impl<'a, REG> ResponseLengthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn short(self) -> &'a mut crate::W<REG> {
        self.variant(ResponseLength::Short)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn long(self) -> &'a mut crate::W<REG> {
        self.variant(ResponseLength::Long)
    }
}
#[doc = "Some of command responses do not return valid CRC bits. Software should disable CRC checks for those commands in order to disable CRC checking by controller.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckResponseCrc {
    #[doc = "0: `0`"]
    Nochk = 0,
    #[doc = "1: `1`"]
    Chk = 1,
}
impl From<CheckResponseCrc> for bool {
    #[inline(always)]
    fn from(variant: CheckResponseCrc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `check_response_crc` reader - Some of command responses do not return valid CRC bits. Software should disable CRC checks for those commands in order to disable CRC checking by controller."]
pub type CheckResponseCrcR = crate::BitReader<CheckResponseCrc>;
impl CheckResponseCrcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CheckResponseCrc {
        match self.bits {
            false => CheckResponseCrc::Nochk,
            true => CheckResponseCrc::Chk,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochk(&self) -> bool {
        *self == CheckResponseCrc::Nochk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_chk(&self) -> bool {
        *self == CheckResponseCrc::Chk
    }
}
#[doc = "Field `check_response_crc` writer - Some of command responses do not return valid CRC bits. Software should disable CRC checks for those commands in order to disable CRC checking by controller."]
pub type CheckResponseCrcW<'a, REG> = crate::BitWriter<'a, REG, CheckResponseCrc>;
impl<'a, REG> CheckResponseCrcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nochk(self) -> &'a mut crate::W<REG> {
        self.variant(CheckResponseCrc::Nochk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn chk(self) -> &'a mut crate::W<REG> {
        self.variant(CheckResponseCrc::Chk)
    }
}
#[doc = "Set decision on data transfer expecetd or not.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataExpected {
    #[doc = "0: `0`"]
    Nodatxferexp = 0,
    #[doc = "1: `1`"]
    Dataxferexp = 1,
}
impl From<DataExpected> for bool {
    #[inline(always)]
    fn from(variant: DataExpected) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `data_expected` reader - Set decision on data transfer expecetd or not."]
pub type DataExpectedR = crate::BitReader<DataExpected>;
impl DataExpectedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DataExpected {
        match self.bits {
            false => DataExpected::Nodatxferexp,
            true => DataExpected::Dataxferexp,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nodatxferexp(&self) -> bool {
        *self == DataExpected::Nodatxferexp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dataxferexp(&self) -> bool {
        *self == DataExpected::Dataxferexp
    }
}
#[doc = "Field `data_expected` writer - Set decision on data transfer expecetd or not."]
pub type DataExpectedW<'a, REG> = crate::BitWriter<'a, REG, DataExpected>;
impl<'a, REG> DataExpectedW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nodatxferexp(self) -> &'a mut crate::W<REG> {
        self.variant(DataExpected::Nodatxferexp)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dataxferexp(self) -> &'a mut crate::W<REG> {
        self.variant(DataExpected::Dataxferexp)
    }
}
#[doc = "Read/Write from card. Don't care if no data transfer expected.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadWrite {
    #[doc = "0: `0`"]
    Rd = 0,
    #[doc = "1: `1`"]
    Wr = 1,
}
impl From<ReadWrite> for bool {
    #[inline(always)]
    fn from(variant: ReadWrite) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `read_write` reader - Read/Write from card. Don't care if no data transfer expected."]
pub type ReadWriteR = crate::BitReader<ReadWrite>;
impl ReadWriteR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ReadWrite {
        match self.bits {
            false => ReadWrite::Rd,
            true => ReadWrite::Wr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rd(&self) -> bool {
        *self == ReadWrite::Rd
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_wr(&self) -> bool {
        *self == ReadWrite::Wr
    }
}
#[doc = "Field `read_write` writer - Read/Write from card. Don't care if no data transfer expected."]
pub type ReadWriteW<'a, REG> = crate::BitWriter<'a, REG, ReadWrite>;
impl<'a, REG> ReadWriteW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rd(self) -> &'a mut crate::W<REG> {
        self.variant(ReadWrite::Rd)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn wr(self) -> &'a mut crate::W<REG> {
        self.variant(ReadWrite::Wr)
    }
}
#[doc = "Block transfer command. Don't care if no data expected\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferMode {
    #[doc = "0: `0`"]
    Blk = 0,
    #[doc = "1: `1`"]
    Str = 1,
}
impl From<TransferMode> for bool {
    #[inline(always)]
    fn from(variant: TransferMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `transfer_mode` reader - Block transfer command. Don't care if no data expected"]
pub type TransferModeR = crate::BitReader<TransferMode>;
impl TransferModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TransferMode {
        match self.bits {
            false => TransferMode::Blk,
            true => TransferMode::Str,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_blk(&self) -> bool {
        *self == TransferMode::Blk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_str(&self) -> bool {
        *self == TransferMode::Str
    }
}
#[doc = "Field `transfer_mode` writer - Block transfer command. Don't care if no data expected"]
pub type TransferModeW<'a, REG> = crate::BitWriter<'a, REG, TransferMode>;
impl<'a, REG> TransferModeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn blk(self) -> &'a mut crate::W<REG> {
        self.variant(TransferMode::Blk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn str(self) -> &'a mut crate::W<REG> {
        self.variant(TransferMode::Str)
    }
}
#[doc = "When set, SD/MMC sends stop command to SD_MMC_CEATA cards at end of data transfer. Determine the following: *-when send_auto_stop bit should be set, since some data transfers do not need explicit stop commands. *-open-ended transfers that software should explicitly send to stop command. Additionally, when resume is sent to resume- suspended memory access of SD-Combo card, bit should be set correctly if suspended data transfer needs send_auto_stop. Don't care if no data expected from card.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendAutoStop {
    #[doc = "0: `0`"]
    Nosend = 0,
    #[doc = "1: `1`"]
    Send = 1,
}
impl From<SendAutoStop> for bool {
    #[inline(always)]
    fn from(variant: SendAutoStop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `send_auto_stop` reader - When set, SD/MMC sends stop command to SD_MMC_CEATA cards at end of data transfer. Determine the following: *-when send_auto_stop bit should be set, since some data transfers do not need explicit stop commands. *-open-ended transfers that software should explicitly send to stop command. Additionally, when resume is sent to resume- suspended memory access of SD-Combo card, bit should be set correctly if suspended data transfer needs send_auto_stop. Don't care if no data expected from card."]
pub type SendAutoStopR = crate::BitReader<SendAutoStop>;
impl SendAutoStopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SendAutoStop {
        match self.bits {
            false => SendAutoStop::Nosend,
            true => SendAutoStop::Send,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nosend(&self) -> bool {
        *self == SendAutoStop::Nosend
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_send(&self) -> bool {
        *self == SendAutoStop::Send
    }
}
#[doc = "Field `send_auto_stop` writer - When set, SD/MMC sends stop command to SD_MMC_CEATA cards at end of data transfer. Determine the following: *-when send_auto_stop bit should be set, since some data transfers do not need explicit stop commands. *-open-ended transfers that software should explicitly send to stop command. Additionally, when resume is sent to resume- suspended memory access of SD-Combo card, bit should be set correctly if suspended data transfer needs send_auto_stop. Don't care if no data expected from card."]
pub type SendAutoStopW<'a, REG> = crate::BitWriter<'a, REG, SendAutoStop>;
impl<'a, REG> SendAutoStopW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nosend(self) -> &'a mut crate::W<REG> {
        self.variant(SendAutoStop::Nosend)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn send(self) -> &'a mut crate::W<REG> {
        self.variant(SendAutoStop::Send)
    }
}
#[doc = "Determines when command is sent. The send command at once option is typically used to query status of card during data transfer or to stop current data transfer.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitPrvdataComplete {
    #[doc = "0: `0`"]
    Nowait = 0,
    #[doc = "1: `1`"]
    Wait = 1,
}
impl From<WaitPrvdataComplete> for bool {
    #[inline(always)]
    fn from(variant: WaitPrvdataComplete) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wait_prvdata_complete` reader - Determines when command is sent. The send command at once option is typically used to query status of card during data transfer or to stop current data transfer."]
pub type WaitPrvdataCompleteR = crate::BitReader<WaitPrvdataComplete>;
impl WaitPrvdataCompleteR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> WaitPrvdataComplete {
        match self.bits {
            false => WaitPrvdataComplete::Nowait,
            true => WaitPrvdataComplete::Wait,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nowait(&self) -> bool {
        *self == WaitPrvdataComplete::Nowait
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_wait(&self) -> bool {
        *self == WaitPrvdataComplete::Wait
    }
}
#[doc = "Field `wait_prvdata_complete` writer - Determines when command is sent. The send command at once option is typically used to query status of card during data transfer or to stop current data transfer."]
pub type WaitPrvdataCompleteW<'a, REG> = crate::BitWriter<'a, REG, WaitPrvdataComplete>;
impl<'a, REG> WaitPrvdataCompleteW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nowait(self) -> &'a mut crate::W<REG> {
        self.variant(WaitPrvdataComplete::Nowait)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn wait(self) -> &'a mut crate::W<REG> {
        self.variant(WaitPrvdataComplete::Wait)
    }
}
#[doc = "When open-ended or predefined data transfer is in progress, and host issues stop or abort command to stop data transfer, bit should be set so that command/data state-machines of CIU can return correctly to idle state. This is also applicable for Boot mode transfers. To Abort boot mode, this bit should be set along with CMD\\[26\\]
= disable_boot. Note: If abort is sent to function-number currently selected or not in data-transfer mode, then bit should be set to 0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopAbortCmd {
    #[doc = "0: `0`"]
    Nostopabrt = 0,
    #[doc = "1: `1`"]
    Stopabrt = 1,
}
impl From<StopAbortCmd> for bool {
    #[inline(always)]
    fn from(variant: StopAbortCmd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stop_abort_cmd` reader - When open-ended or predefined data transfer is in progress, and host issues stop or abort command to stop data transfer, bit should be set so that command/data state-machines of CIU can return correctly to idle state. This is also applicable for Boot mode transfers. To Abort boot mode, this bit should be set along with CMD\\[26\\]
= disable_boot. Note: If abort is sent to function-number currently selected or not in data-transfer mode, then bit should be set to 0."]
pub type StopAbortCmdR = crate::BitReader<StopAbortCmd>;
impl StopAbortCmdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> StopAbortCmd {
        match self.bits {
            false => StopAbortCmd::Nostopabrt,
            true => StopAbortCmd::Stopabrt,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nostopabrt(&self) -> bool {
        *self == StopAbortCmd::Nostopabrt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_stopabrt(&self) -> bool {
        *self == StopAbortCmd::Stopabrt
    }
}
#[doc = "Field `stop_abort_cmd` writer - When open-ended or predefined data transfer is in progress, and host issues stop or abort command to stop data transfer, bit should be set so that command/data state-machines of CIU can return correctly to idle state. This is also applicable for Boot mode transfers. To Abort boot mode, this bit should be set along with CMD\\[26\\]
= disable_boot. Note: If abort is sent to function-number currently selected or not in data-transfer mode, then bit should be set to 0."]
pub type StopAbortCmdW<'a, REG> = crate::BitWriter<'a, REG, StopAbortCmd>;
impl<'a, REG> StopAbortCmdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nostopabrt(self) -> &'a mut crate::W<REG> {
        self.variant(StopAbortCmd::Nostopabrt)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn stopabrt(self) -> &'a mut crate::W<REG> {
        self.variant(StopAbortCmd::Stopabrt)
    }
}
#[doc = "After power on, 80 clocks must be sent to the card for initialization before sending any commands to card. Bit should be set while sending first command to card so that controller will initialize clocks before sending command to card. This bit should not be set for either of the boot modes (alternate or mandatory).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendInitialization {
    #[doc = "0: `0`"]
    Noinit = 0,
    #[doc = "1: `1`"]
    Init = 1,
}
impl From<SendInitialization> for bool {
    #[inline(always)]
    fn from(variant: SendInitialization) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `send_initialization` reader - After power on, 80 clocks must be sent to the card for initialization before sending any commands to card. Bit should be set while sending first command to card so that controller will initialize clocks before sending command to card. This bit should not be set for either of the boot modes (alternate or mandatory)."]
pub type SendInitializationR = crate::BitReader<SendInitialization>;
impl SendInitializationR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SendInitialization {
        match self.bits {
            false => SendInitialization::Noinit,
            true => SendInitialization::Init,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noinit(&self) -> bool {
        *self == SendInitialization::Noinit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_init(&self) -> bool {
        *self == SendInitialization::Init
    }
}
#[doc = "Field `send_initialization` writer - After power on, 80 clocks must be sent to the card for initialization before sending any commands to card. Bit should be set while sending first command to card so that controller will initialize clocks before sending command to card. This bit should not be set for either of the boot modes (alternate or mandatory)."]
pub type SendInitializationW<'a, REG> = crate::BitWriter<'a, REG, SendInitialization>;
impl<'a, REG> SendInitializationW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noinit(self) -> &'a mut crate::W<REG> {
        self.variant(SendInitialization::Noinit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn init(self) -> &'a mut crate::W<REG> {
        self.variant(SendInitialization::Init)
    }
}
#[doc = "Field `card_number` reader - Card number in use must always be 0."]
pub type CardNumberR = crate::FieldReader;
#[doc = "Field `card_number` writer - Card number in use must always be 0."]
pub type CardNumberW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Following register values transferred into card clock domain: CLKDIV, CLRSRC, CLKENA. Changes card clocks (change frequency, truncate off or on, and set low-frequency mode); provided in order to change clock frequency or stop clock without having to send command to cards. During normal command sequence, when update_clock_registers_only = 0, following control registers are transferred from BIU to CIU: CMD, CMDARG, TMOUT, CTYPE, BLKSIZ, BYTCNT. CIU uses new register values for new command sequence to card(s). When bit is set, there are no Command Done interrupts because no command is sent to SD_MMC_CEATA cards.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateClockRegistersOnly {
    #[doc = "0: `0`"]
    Normcmd = 0,
    #[doc = "1: `1`"]
    Updatclkreg = 1,
}
impl From<UpdateClockRegistersOnly> for bool {
    #[inline(always)]
    fn from(variant: UpdateClockRegistersOnly) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `update_clock_registers_only` reader - Following register values transferred into card clock domain: CLKDIV, CLRSRC, CLKENA. Changes card clocks (change frequency, truncate off or on, and set low-frequency mode); provided in order to change clock frequency or stop clock without having to send command to cards. During normal command sequence, when update_clock_registers_only = 0, following control registers are transferred from BIU to CIU: CMD, CMDARG, TMOUT, CTYPE, BLKSIZ, BYTCNT. CIU uses new register values for new command sequence to card(s). When bit is set, there are no Command Done interrupts because no command is sent to SD_MMC_CEATA cards."]
pub type UpdateClockRegistersOnlyR = crate::BitReader<UpdateClockRegistersOnly>;
impl UpdateClockRegistersOnlyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> UpdateClockRegistersOnly {
        match self.bits {
            false => UpdateClockRegistersOnly::Normcmd,
            true => UpdateClockRegistersOnly::Updatclkreg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_normcmd(&self) -> bool {
        *self == UpdateClockRegistersOnly::Normcmd
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_updatclkreg(&self) -> bool {
        *self == UpdateClockRegistersOnly::Updatclkreg
    }
}
#[doc = "Field `update_clock_registers_only` writer - Following register values transferred into card clock domain: CLKDIV, CLRSRC, CLKENA. Changes card clocks (change frequency, truncate off or on, and set low-frequency mode); provided in order to change clock frequency or stop clock without having to send command to cards. During normal command sequence, when update_clock_registers_only = 0, following control registers are transferred from BIU to CIU: CMD, CMDARG, TMOUT, CTYPE, BLKSIZ, BYTCNT. CIU uses new register values for new command sequence to card(s). When bit is set, there are no Command Done interrupts because no command is sent to SD_MMC_CEATA cards."]
pub type UpdateClockRegistersOnlyW<'a, REG> = crate::BitWriter<'a, REG, UpdateClockRegistersOnly>;
impl<'a, REG> UpdateClockRegistersOnlyW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn normcmd(self) -> &'a mut crate::W<REG> {
        self.variant(UpdateClockRegistersOnly::Normcmd)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn updatclkreg(self) -> &'a mut crate::W<REG> {
        self.variant(UpdateClockRegistersOnly::Updatclkreg)
    }
}
#[doc = "Software should set this bit to indicate that CE-ATA device is being accessed for read transfer. This bit is used to disable read data timeout indication while performing CE-ATA read transfers. Maximum value of I/O transmission delay can be no less than 10 seconds. SD/MMC should not indicate read data timeout while waiting for data from CE-ATA device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadCeataDevice {
    #[doc = "0: `0`"]
    Nord = 0,
    #[doc = "1: `1`"]
    Rd = 1,
}
impl From<ReadCeataDevice> for bool {
    #[inline(always)]
    fn from(variant: ReadCeataDevice) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `read_ceata_device` reader - Software should set this bit to indicate that CE-ATA device is being accessed for read transfer. This bit is used to disable read data timeout indication while performing CE-ATA read transfers. Maximum value of I/O transmission delay can be no less than 10 seconds. SD/MMC should not indicate read data timeout while waiting for data from CE-ATA device."]
pub type ReadCeataDeviceR = crate::BitReader<ReadCeataDevice>;
impl ReadCeataDeviceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ReadCeataDevice {
        match self.bits {
            false => ReadCeataDevice::Nord,
            true => ReadCeataDevice::Rd,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nord(&self) -> bool {
        *self == ReadCeataDevice::Nord
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rd(&self) -> bool {
        *self == ReadCeataDevice::Rd
    }
}
#[doc = "Field `read_ceata_device` writer - Software should set this bit to indicate that CE-ATA device is being accessed for read transfer. This bit is used to disable read data timeout indication while performing CE-ATA read transfers. Maximum value of I/O transmission delay can be no less than 10 seconds. SD/MMC should not indicate read data timeout while waiting for data from CE-ATA device."]
pub type ReadCeataDeviceW<'a, REG> = crate::BitWriter<'a, REG, ReadCeataDevice>;
impl<'a, REG> ReadCeataDeviceW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nord(self) -> &'a mut crate::W<REG> {
        self.variant(ReadCeataDevice::Nord)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rd(self) -> &'a mut crate::W<REG> {
        self.variant(ReadCeataDevice::Rd)
    }
}
#[doc = "If the command expects Command Completion Signal (CCS) from the CE-ATA device, the software should set this control bit. SD/MMC sets Data Transfer Over (DTO) bit in RINTSTS register and generates interrupt to host if Data Transfer Over interrupt is not masked.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcsExpected {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<CcsExpected> for bool {
    #[inline(always)]
    fn from(variant: CcsExpected) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ccs_expected` reader - If the command expects Command Completion Signal (CCS) from the CE-ATA device, the software should set this control bit. SD/MMC sets Data Transfer Over (DTO) bit in RINTSTS register and generates interrupt to host if Data Transfer Over interrupt is not masked."]
pub type CcsExpectedR = crate::BitReader<CcsExpected>;
impl CcsExpectedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CcsExpected {
        match self.bits {
            false => CcsExpected::Disabled,
            true => CcsExpected::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == CcsExpected::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == CcsExpected::Enabled
    }
}
#[doc = "Field `ccs_expected` writer - If the command expects Command Completion Signal (CCS) from the CE-ATA device, the software should set this control bit. SD/MMC sets Data Transfer Over (DTO) bit in RINTSTS register and generates interrupt to host if Data Transfer Over interrupt is not masked."]
pub type CcsExpectedW<'a, REG> = crate::BitWriter<'a, REG, CcsExpected>;
impl<'a, REG> CcsExpectedW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(CcsExpected::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(CcsExpected::Enabled)
    }
}
#[doc = "This bit should be set only for mandatory boot mode. When Software sets this bit along with start_cmd, CIU starts the boot sequence for the corresponding card by asserting the CMD line low. Do NOT set disable_boot and enable_boot together\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnableBoot {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<EnableBoot> for bool {
    #[inline(always)]
    fn from(variant: EnableBoot) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enable_boot` reader - This bit should be set only for mandatory boot mode. When Software sets this bit along with start_cmd, CIU starts the boot sequence for the corresponding card by asserting the CMD line low. Do NOT set disable_boot and enable_boot together"]
pub type EnableBootR = crate::BitReader<EnableBoot>;
impl EnableBootR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> EnableBoot {
        match self.bits {
            false => EnableBoot::Disabled,
            true => EnableBoot::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == EnableBoot::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == EnableBoot::Enabled
    }
}
#[doc = "Field `enable_boot` writer - This bit should be set only for mandatory boot mode. When Software sets this bit along with start_cmd, CIU starts the boot sequence for the corresponding card by asserting the CMD line low. Do NOT set disable_boot and enable_boot together"]
pub type EnableBootW<'a, REG> = crate::BitWriter<'a, REG, EnableBoot>;
impl<'a, REG> EnableBootW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(EnableBoot::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(EnableBoot::Enabled)
    }
}
#[doc = "When Software sets this bit along with enable_boot, CIU expects a boot acknowledge start pattern of 0-1-0 from the selected card.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectBootAck {
    #[doc = "0: `0`"]
    Nobootack = 0,
    #[doc = "1: `1`"]
    Bootack = 1,
}
impl From<ExpectBootAck> for bool {
    #[inline(always)]
    fn from(variant: ExpectBootAck) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `expect_boot_ack` reader - When Software sets this bit along with enable_boot, CIU expects a boot acknowledge start pattern of 0-1-0 from the selected card."]
pub type ExpectBootAckR = crate::BitReader<ExpectBootAck>;
impl ExpectBootAckR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ExpectBootAck {
        match self.bits {
            false => ExpectBootAck::Nobootack,
            true => ExpectBootAck::Bootack,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nobootack(&self) -> bool {
        *self == ExpectBootAck::Nobootack
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_bootack(&self) -> bool {
        *self == ExpectBootAck::Bootack
    }
}
#[doc = "Field `expect_boot_ack` writer - When Software sets this bit along with enable_boot, CIU expects a boot acknowledge start pattern of 0-1-0 from the selected card."]
pub type ExpectBootAckW<'a, REG> = crate::BitWriter<'a, REG, ExpectBootAck>;
impl<'a, REG> ExpectBootAckW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nobootack(self) -> &'a mut crate::W<REG> {
        self.variant(ExpectBootAck::Nobootack)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn bootack(self) -> &'a mut crate::W<REG> {
        self.variant(ExpectBootAck::Bootack)
    }
}
#[doc = "When software sets this bit along with start_cmd, CIU terminates the boot operation. Do NOT set disable_boot and enable_boot together.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisableBoot {
    #[doc = "0: `0`"]
    Notermboot = 0,
    #[doc = "1: `1`"]
    Termboot = 1,
}
impl From<DisableBoot> for bool {
    #[inline(always)]
    fn from(variant: DisableBoot) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `disable_boot` reader - When software sets this bit along with start_cmd, CIU terminates the boot operation. Do NOT set disable_boot and enable_boot together."]
pub type DisableBootR = crate::BitReader<DisableBoot>;
impl DisableBootR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DisableBoot {
        match self.bits {
            false => DisableBoot::Notermboot,
            true => DisableBoot::Termboot,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notermboot(&self) -> bool {
        *self == DisableBoot::Notermboot
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_termboot(&self) -> bool {
        *self == DisableBoot::Termboot
    }
}
#[doc = "Field `disable_boot` writer - When software sets this bit along with start_cmd, CIU terminates the boot operation. Do NOT set disable_boot and enable_boot together."]
pub type DisableBootW<'a, REG> = crate::BitWriter<'a, REG, DisableBoot>;
impl<'a, REG> DisableBootW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notermboot(self) -> &'a mut crate::W<REG> {
        self.variant(DisableBoot::Notermboot)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn termboot(self) -> &'a mut crate::W<REG> {
        self.variant(DisableBoot::Termboot)
    }
}
#[doc = "Type of Boot Mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMode {
    #[doc = "0: `0`"]
    Mandatory = 0,
    #[doc = "1: `1`"]
    Alternate = 1,
}
impl From<BootMode> for bool {
    #[inline(always)]
    fn from(variant: BootMode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `boot_mode` reader - Type of Boot Mode."]
pub type BootModeR = crate::BitReader<BootMode>;
impl BootModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> BootMode {
        match self.bits {
            false => BootMode::Mandatory,
            true => BootMode::Alternate,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mandatory(&self) -> bool {
        *self == BootMode::Mandatory
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_alternate(&self) -> bool {
        *self == BootMode::Alternate
    }
}
#[doc = "Field `boot_mode` writer - Type of Boot Mode."]
pub type BootModeW<'a, REG> = crate::BitWriter<'a, REG, BootMode>;
impl<'a, REG> BootModeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mandatory(self) -> &'a mut crate::W<REG> {
        self.variant(BootMode::Mandatory)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn alternate(self) -> &'a mut crate::W<REG> {
        self.variant(BootMode::Alternate)
    }
}
#[doc = "Voltage switch bit. When set must be set for CMD11 only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoltSwitch {
    #[doc = "0: `0`"]
    Novoltsw = 0,
    #[doc = "1: `1`"]
    Voltsw = 1,
}
impl From<VoltSwitch> for bool {
    #[inline(always)]
    fn from(variant: VoltSwitch) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `volt_switch` reader - Voltage switch bit. When set must be set for CMD11 only."]
pub type VoltSwitchR = crate::BitReader<VoltSwitch>;
impl VoltSwitchR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> VoltSwitch {
        match self.bits {
            false => VoltSwitch::Novoltsw,
            true => VoltSwitch::Voltsw,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_novoltsw(&self) -> bool {
        *self == VoltSwitch::Novoltsw
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_voltsw(&self) -> bool {
        *self == VoltSwitch::Voltsw
    }
}
#[doc = "Field `volt_switch` writer - Voltage switch bit. When set must be set for CMD11 only."]
pub type VoltSwitchW<'a, REG> = crate::BitWriter<'a, REG, VoltSwitch>;
impl<'a, REG> VoltSwitchW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn novoltsw(self) -> &'a mut crate::W<REG> {
        self.variant(VoltSwitch::Novoltsw)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn voltsw(self) -> &'a mut crate::W<REG> {
        self.variant(VoltSwitch::Voltsw)
    }
}
#[doc = "Set to one for SDR12 and SDR25 (with non-zero phase-shifted cclk_in_drv); zero phase shift is not allowed in these modes. -Set to 1'b0 for SDR50, SDR104, and DDR50 (with zero phase-shifted cclk_in_drv). -Set to 1'b1 for SDR50, SDR104, and DDR50 (with non-zero phase-shifted cclk_in_drv).\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UseHoldReg {
    #[doc = "0: `0`"]
    Bypass = 0,
    #[doc = "1: `1`"]
    Nobypass = 1,
}
impl From<UseHoldReg> for bool {
    #[inline(always)]
    fn from(variant: UseHoldReg) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `use_hold_reg` reader - Set to one for SDR12 and SDR25 (with non-zero phase-shifted cclk_in_drv); zero phase shift is not allowed in these modes. -Set to 1'b0 for SDR50, SDR104, and DDR50 (with zero phase-shifted cclk_in_drv). -Set to 1'b1 for SDR50, SDR104, and DDR50 (with non-zero phase-shifted cclk_in_drv)."]
pub type UseHoldRegR = crate::BitReader<UseHoldReg>;
impl UseHoldRegR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> UseHoldReg {
        match self.bits {
            false => UseHoldReg::Bypass,
            true => UseHoldReg::Nobypass,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_bypass(&self) -> bool {
        *self == UseHoldReg::Bypass
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nobypass(&self) -> bool {
        *self == UseHoldReg::Nobypass
    }
}
#[doc = "Field `use_hold_reg` writer - Set to one for SDR12 and SDR25 (with non-zero phase-shifted cclk_in_drv); zero phase shift is not allowed in these modes. -Set to 1'b0 for SDR50, SDR104, and DDR50 (with zero phase-shifted cclk_in_drv). -Set to 1'b1 for SDR50, SDR104, and DDR50 (with non-zero phase-shifted cclk_in_drv)."]
pub type UseHoldRegW<'a, REG> = crate::BitWriter<'a, REG, UseHoldReg>;
impl<'a, REG> UseHoldRegW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn bypass(self) -> &'a mut crate::W<REG> {
        self.variant(UseHoldReg::Bypass)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nobypass(self) -> &'a mut crate::W<REG> {
        self.variant(UseHoldReg::Nobypass)
    }
}
#[doc = "Once command is taken by CIU, bit is cleared. If Start Cmd issued host should not attempt to write to any command registers. If write is attempted, hardware lock error is set in raw interrupt register. Once command is sent and response is received from SD_MMC_CEATA cards, Command Done bit is set in raw interrupt register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartCmd {
    #[doc = "0: `0`"]
    Nostart = 0,
    #[doc = "1: `1`"]
    Start = 1,
}
impl From<StartCmd> for bool {
    #[inline(always)]
    fn from(variant: StartCmd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `start_cmd` reader - Once command is taken by CIU, bit is cleared. If Start Cmd issued host should not attempt to write to any command registers. If write is attempted, hardware lock error is set in raw interrupt register. Once command is sent and response is received from SD_MMC_CEATA cards, Command Done bit is set in raw interrupt register."]
pub type StartCmdR = crate::BitReader<StartCmd>;
impl StartCmdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> StartCmd {
        match self.bits {
            false => StartCmd::Nostart,
            true => StartCmd::Start,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nostart(&self) -> bool {
        *self == StartCmd::Nostart
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_start(&self) -> bool {
        *self == StartCmd::Start
    }
}
#[doc = "Field `start_cmd` writer - Once command is taken by CIU, bit is cleared. If Start Cmd issued host should not attempt to write to any command registers. If write is attempted, hardware lock error is set in raw interrupt register. Once command is sent and response is received from SD_MMC_CEATA cards, Command Done bit is set in raw interrupt register."]
pub type StartCmdW<'a, REG> = crate::BitWriter<'a, REG, StartCmd>;
impl<'a, REG> StartCmdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nostart(self) -> &'a mut crate::W<REG> {
        self.variant(StartCmd::Nostart)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn start(self) -> &'a mut crate::W<REG> {
        self.variant(StartCmd::Start)
    }
}
impl R {
    #[doc = "Bits 0:5 - Tracks the command index number. Values from 0-31."]
    #[inline(always)]
    pub fn cmd_index(&self) -> CmdIndexR {
        CmdIndexR::new((self.bits & 0x3f) as u8)
    }
    #[doc = "Bit 6 - Response expected from card."]
    #[inline(always)]
    pub fn response_expect(&self) -> ResponseExpectR {
        ResponseExpectR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Provides long and short response"]
    #[inline(always)]
    pub fn response_length(&self) -> ResponseLengthR {
        ResponseLengthR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Some of command responses do not return valid CRC bits. Software should disable CRC checks for those commands in order to disable CRC checking by controller."]
    #[inline(always)]
    pub fn check_response_crc(&self) -> CheckResponseCrcR {
        CheckResponseCrcR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Set decision on data transfer expecetd or not."]
    #[inline(always)]
    pub fn data_expected(&self) -> DataExpectedR {
        DataExpectedR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Read/Write from card. Don't care if no data transfer expected."]
    #[inline(always)]
    pub fn read_write(&self) -> ReadWriteR {
        ReadWriteR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Block transfer command. Don't care if no data expected"]
    #[inline(always)]
    pub fn transfer_mode(&self) -> TransferModeR {
        TransferModeR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - When set, SD/MMC sends stop command to SD_MMC_CEATA cards at end of data transfer. Determine the following: *-when send_auto_stop bit should be set, since some data transfers do not need explicit stop commands. *-open-ended transfers that software should explicitly send to stop command. Additionally, when resume is sent to resume- suspended memory access of SD-Combo card, bit should be set correctly if suspended data transfer needs send_auto_stop. Don't care if no data expected from card."]
    #[inline(always)]
    pub fn send_auto_stop(&self) -> SendAutoStopR {
        SendAutoStopR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Determines when command is sent. The send command at once option is typically used to query status of card during data transfer or to stop current data transfer."]
    #[inline(always)]
    pub fn wait_prvdata_complete(&self) -> WaitPrvdataCompleteR {
        WaitPrvdataCompleteR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - When open-ended or predefined data transfer is in progress, and host issues stop or abort command to stop data transfer, bit should be set so that command/data state-machines of CIU can return correctly to idle state. This is also applicable for Boot mode transfers. To Abort boot mode, this bit should be set along with CMD\\[26\\]
= disable_boot. Note: If abort is sent to function-number currently selected or not in data-transfer mode, then bit should be set to 0."]
    #[inline(always)]
    pub fn stop_abort_cmd(&self) -> StopAbortCmdR {
        StopAbortCmdR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - After power on, 80 clocks must be sent to the card for initialization before sending any commands to card. Bit should be set while sending first command to card so that controller will initialize clocks before sending command to card. This bit should not be set for either of the boot modes (alternate or mandatory)."]
    #[inline(always)]
    pub fn send_initialization(&self) -> SendInitializationR {
        SendInitializationR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:20 - Card number in use must always be 0."]
    #[inline(always)]
    pub fn card_number(&self) -> CardNumberR {
        CardNumberR::new(((self.bits >> 16) & 0x1f) as u8)
    }
    #[doc = "Bit 21 - Following register values transferred into card clock domain: CLKDIV, CLRSRC, CLKENA. Changes card clocks (change frequency, truncate off or on, and set low-frequency mode); provided in order to change clock frequency or stop clock without having to send command to cards. During normal command sequence, when update_clock_registers_only = 0, following control registers are transferred from BIU to CIU: CMD, CMDARG, TMOUT, CTYPE, BLKSIZ, BYTCNT. CIU uses new register values for new command sequence to card(s). When bit is set, there are no Command Done interrupts because no command is sent to SD_MMC_CEATA cards."]
    #[inline(always)]
    pub fn update_clock_registers_only(&self) -> UpdateClockRegistersOnlyR {
        UpdateClockRegistersOnlyR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Software should set this bit to indicate that CE-ATA device is being accessed for read transfer. This bit is used to disable read data timeout indication while performing CE-ATA read transfers. Maximum value of I/O transmission delay can be no less than 10 seconds. SD/MMC should not indicate read data timeout while waiting for data from CE-ATA device."]
    #[inline(always)]
    pub fn read_ceata_device(&self) -> ReadCeataDeviceR {
        ReadCeataDeviceR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - If the command expects Command Completion Signal (CCS) from the CE-ATA device, the software should set this control bit. SD/MMC sets Data Transfer Over (DTO) bit in RINTSTS register and generates interrupt to host if Data Transfer Over interrupt is not masked."]
    #[inline(always)]
    pub fn ccs_expected(&self) -> CcsExpectedR {
        CcsExpectedR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - This bit should be set only for mandatory boot mode. When Software sets this bit along with start_cmd, CIU starts the boot sequence for the corresponding card by asserting the CMD line low. Do NOT set disable_boot and enable_boot together"]
    #[inline(always)]
    pub fn enable_boot(&self) -> EnableBootR {
        EnableBootR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - When Software sets this bit along with enable_boot, CIU expects a boot acknowledge start pattern of 0-1-0 from the selected card."]
    #[inline(always)]
    pub fn expect_boot_ack(&self) -> ExpectBootAckR {
        ExpectBootAckR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - When software sets this bit along with start_cmd, CIU terminates the boot operation. Do NOT set disable_boot and enable_boot together."]
    #[inline(always)]
    pub fn disable_boot(&self) -> DisableBootR {
        DisableBootR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Type of Boot Mode."]
    #[inline(always)]
    pub fn boot_mode(&self) -> BootModeR {
        BootModeR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Voltage switch bit. When set must be set for CMD11 only."]
    #[inline(always)]
    pub fn volt_switch(&self) -> VoltSwitchR {
        VoltSwitchR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Set to one for SDR12 and SDR25 (with non-zero phase-shifted cclk_in_drv); zero phase shift is not allowed in these modes. -Set to 1'b0 for SDR50, SDR104, and DDR50 (with zero phase-shifted cclk_in_drv). -Set to 1'b1 for SDR50, SDR104, and DDR50 (with non-zero phase-shifted cclk_in_drv)."]
    #[inline(always)]
    pub fn use_hold_reg(&self) -> UseHoldRegR {
        UseHoldRegR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 31 - Once command is taken by CIU, bit is cleared. If Start Cmd issued host should not attempt to write to any command registers. If write is attempted, hardware lock error is set in raw interrupt register. Once command is sent and response is received from SD_MMC_CEATA cards, Command Done bit is set in raw interrupt register."]
    #[inline(always)]
    pub fn start_cmd(&self) -> StartCmdR {
        StartCmdR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:5 - Tracks the command index number. Values from 0-31."]
    #[inline(always)]
    #[must_use]
    pub fn cmd_index(&mut self) -> CmdIndexW<CmdSpec> {
        CmdIndexW::new(self, 0)
    }
    #[doc = "Bit 6 - Response expected from card."]
    #[inline(always)]
    #[must_use]
    pub fn response_expect(&mut self) -> ResponseExpectW<CmdSpec> {
        ResponseExpectW::new(self, 6)
    }
    #[doc = "Bit 7 - Provides long and short response"]
    #[inline(always)]
    #[must_use]
    pub fn response_length(&mut self) -> ResponseLengthW<CmdSpec> {
        ResponseLengthW::new(self, 7)
    }
    #[doc = "Bit 8 - Some of command responses do not return valid CRC bits. Software should disable CRC checks for those commands in order to disable CRC checking by controller."]
    #[inline(always)]
    #[must_use]
    pub fn check_response_crc(&mut self) -> CheckResponseCrcW<CmdSpec> {
        CheckResponseCrcW::new(self, 8)
    }
    #[doc = "Bit 9 - Set decision on data transfer expecetd or not."]
    #[inline(always)]
    #[must_use]
    pub fn data_expected(&mut self) -> DataExpectedW<CmdSpec> {
        DataExpectedW::new(self, 9)
    }
    #[doc = "Bit 10 - Read/Write from card. Don't care if no data transfer expected."]
    #[inline(always)]
    #[must_use]
    pub fn read_write(&mut self) -> ReadWriteW<CmdSpec> {
        ReadWriteW::new(self, 10)
    }
    #[doc = "Bit 11 - Block transfer command. Don't care if no data expected"]
    #[inline(always)]
    #[must_use]
    pub fn transfer_mode(&mut self) -> TransferModeW<CmdSpec> {
        TransferModeW::new(self, 11)
    }
    #[doc = "Bit 12 - When set, SD/MMC sends stop command to SD_MMC_CEATA cards at end of data transfer. Determine the following: *-when send_auto_stop bit should be set, since some data transfers do not need explicit stop commands. *-open-ended transfers that software should explicitly send to stop command. Additionally, when resume is sent to resume- suspended memory access of SD-Combo card, bit should be set correctly if suspended data transfer needs send_auto_stop. Don't care if no data expected from card."]
    #[inline(always)]
    #[must_use]
    pub fn send_auto_stop(&mut self) -> SendAutoStopW<CmdSpec> {
        SendAutoStopW::new(self, 12)
    }
    #[doc = "Bit 13 - Determines when command is sent. The send command at once option is typically used to query status of card during data transfer or to stop current data transfer."]
    #[inline(always)]
    #[must_use]
    pub fn wait_prvdata_complete(&mut self) -> WaitPrvdataCompleteW<CmdSpec> {
        WaitPrvdataCompleteW::new(self, 13)
    }
    #[doc = "Bit 14 - When open-ended or predefined data transfer is in progress, and host issues stop or abort command to stop data transfer, bit should be set so that command/data state-machines of CIU can return correctly to idle state. This is also applicable for Boot mode transfers. To Abort boot mode, this bit should be set along with CMD\\[26\\]
= disable_boot. Note: If abort is sent to function-number currently selected or not in data-transfer mode, then bit should be set to 0."]
    #[inline(always)]
    #[must_use]
    pub fn stop_abort_cmd(&mut self) -> StopAbortCmdW<CmdSpec> {
        StopAbortCmdW::new(self, 14)
    }
    #[doc = "Bit 15 - After power on, 80 clocks must be sent to the card for initialization before sending any commands to card. Bit should be set while sending first command to card so that controller will initialize clocks before sending command to card. This bit should not be set for either of the boot modes (alternate or mandatory)."]
    #[inline(always)]
    #[must_use]
    pub fn send_initialization(&mut self) -> SendInitializationW<CmdSpec> {
        SendInitializationW::new(self, 15)
    }
    #[doc = "Bits 16:20 - Card number in use must always be 0."]
    #[inline(always)]
    #[must_use]
    pub fn card_number(&mut self) -> CardNumberW<CmdSpec> {
        CardNumberW::new(self, 16)
    }
    #[doc = "Bit 21 - Following register values transferred into card clock domain: CLKDIV, CLRSRC, CLKENA. Changes card clocks (change frequency, truncate off or on, and set low-frequency mode); provided in order to change clock frequency or stop clock without having to send command to cards. During normal command sequence, when update_clock_registers_only = 0, following control registers are transferred from BIU to CIU: CMD, CMDARG, TMOUT, CTYPE, BLKSIZ, BYTCNT. CIU uses new register values for new command sequence to card(s). When bit is set, there are no Command Done interrupts because no command is sent to SD_MMC_CEATA cards."]
    #[inline(always)]
    #[must_use]
    pub fn update_clock_registers_only(&mut self) -> UpdateClockRegistersOnlyW<CmdSpec> {
        UpdateClockRegistersOnlyW::new(self, 21)
    }
    #[doc = "Bit 22 - Software should set this bit to indicate that CE-ATA device is being accessed for read transfer. This bit is used to disable read data timeout indication while performing CE-ATA read transfers. Maximum value of I/O transmission delay can be no less than 10 seconds. SD/MMC should not indicate read data timeout while waiting for data from CE-ATA device."]
    #[inline(always)]
    #[must_use]
    pub fn read_ceata_device(&mut self) -> ReadCeataDeviceW<CmdSpec> {
        ReadCeataDeviceW::new(self, 22)
    }
    #[doc = "Bit 23 - If the command expects Command Completion Signal (CCS) from the CE-ATA device, the software should set this control bit. SD/MMC sets Data Transfer Over (DTO) bit in RINTSTS register and generates interrupt to host if Data Transfer Over interrupt is not masked."]
    #[inline(always)]
    #[must_use]
    pub fn ccs_expected(&mut self) -> CcsExpectedW<CmdSpec> {
        CcsExpectedW::new(self, 23)
    }
    #[doc = "Bit 24 - This bit should be set only for mandatory boot mode. When Software sets this bit along with start_cmd, CIU starts the boot sequence for the corresponding card by asserting the CMD line low. Do NOT set disable_boot and enable_boot together"]
    #[inline(always)]
    #[must_use]
    pub fn enable_boot(&mut self) -> EnableBootW<CmdSpec> {
        EnableBootW::new(self, 24)
    }
    #[doc = "Bit 25 - When Software sets this bit along with enable_boot, CIU expects a boot acknowledge start pattern of 0-1-0 from the selected card."]
    #[inline(always)]
    #[must_use]
    pub fn expect_boot_ack(&mut self) -> ExpectBootAckW<CmdSpec> {
        ExpectBootAckW::new(self, 25)
    }
    #[doc = "Bit 26 - When software sets this bit along with start_cmd, CIU terminates the boot operation. Do NOT set disable_boot and enable_boot together."]
    #[inline(always)]
    #[must_use]
    pub fn disable_boot(&mut self) -> DisableBootW<CmdSpec> {
        DisableBootW::new(self, 26)
    }
    #[doc = "Bit 27 - Type of Boot Mode."]
    #[inline(always)]
    #[must_use]
    pub fn boot_mode(&mut self) -> BootModeW<CmdSpec> {
        BootModeW::new(self, 27)
    }
    #[doc = "Bit 28 - Voltage switch bit. When set must be set for CMD11 only."]
    #[inline(always)]
    #[must_use]
    pub fn volt_switch(&mut self) -> VoltSwitchW<CmdSpec> {
        VoltSwitchW::new(self, 28)
    }
    #[doc = "Bit 29 - Set to one for SDR12 and SDR25 (with non-zero phase-shifted cclk_in_drv); zero phase shift is not allowed in these modes. -Set to 1'b0 for SDR50, SDR104, and DDR50 (with zero phase-shifted cclk_in_drv). -Set to 1'b1 for SDR50, SDR104, and DDR50 (with non-zero phase-shifted cclk_in_drv)."]
    #[inline(always)]
    #[must_use]
    pub fn use_hold_reg(&mut self) -> UseHoldRegW<CmdSpec> {
        UseHoldRegW::new(self, 29)
    }
    #[doc = "Bit 31 - Once command is taken by CIU, bit is cleared. If Start Cmd issued host should not attempt to write to any command registers. If write is attempted, hardware lock error is set in raw interrupt register. Once command is sent and response is received from SD_MMC_CEATA cards, Command Done bit is set in raw interrupt register."]
    #[inline(always)]
    #[must_use]
    pub fn start_cmd(&mut self) -> StartCmdW<CmdSpec> {
        StartCmdW::new(self, 31)
    }
}
#[doc = "This register issues various commands.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cmd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CmdSpec;
impl crate::RegisterSpec for CmdSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`cmd::R`](R) reader structure"]
impl crate::Readable for CmdSpec {}
#[doc = "`write(|w| ..)` method takes [`cmd::W`](W) writer structure"]
impl crate::Writable for CmdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets cmd to value 0x2000_0000"]
impl crate::Resettable for CmdSpec {
    const RESET_VALUE: u32 = 0x2000_0000;
}
