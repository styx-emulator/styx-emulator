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
#[doc = "Register `dmagrp_Operation_Mode` reader"]
pub type R = crate::R<DmagrpOperationModeSpec>;
#[doc = "Register `dmagrp_Operation_Mode` writer"]
pub type W = crate::W<DmagrpOperationModeSpec>;
#[doc = "When this bit is set, the Receive process is placed in the Running state. The DMA attempts to acquire the descriptor from the Receive list and processes the incoming frames. The descriptor acquisition is attempted from the current position in the list, which is the address set by Register 3 (Receive Descriptor List Address Register) or the position retained when the Receive process was previously stopped. If the DMA does not own the descriptor, reception is suspended and Bit 7 (Receive Buffer Unavailable) of Register 5 (Status Register) is set. The Start Receive command is effective only when the reception has stopped. If the command is issued before setting Register 3 (Receive Descriptor List Address Register), the DMA behavior is unpredictable. When this bit is cleared, the Rx DMA operation is stopped after the transfer of the current frame. The next descriptor position in the Receive list is saved and becomes the current position after the Receive process is restarted. The Stop Receive command is effective only when the Receive process is in either the Running (waiting for receive packet) or in the Suspended state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sr {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sr> for bool {
    #[inline(always)]
    fn from(variant: Sr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sr` reader - When this bit is set, the Receive process is placed in the Running state. The DMA attempts to acquire the descriptor from the Receive list and processes the incoming frames. The descriptor acquisition is attempted from the current position in the list, which is the address set by Register 3 (Receive Descriptor List Address Register) or the position retained when the Receive process was previously stopped. If the DMA does not own the descriptor, reception is suspended and Bit 7 (Receive Buffer Unavailable) of Register 5 (Status Register) is set. The Start Receive command is effective only when the reception has stopped. If the command is issued before setting Register 3 (Receive Descriptor List Address Register), the DMA behavior is unpredictable. When this bit is cleared, the Rx DMA operation is stopped after the transfer of the current frame. The next descriptor position in the Receive list is saved and becomes the current position after the Receive process is restarted. The Stop Receive command is effective only when the Receive process is in either the Running (waiting for receive packet) or in the Suspended state."]
pub type SrR = crate::BitReader<Sr>;
impl SrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sr {
        match self.bits {
            false => Sr::Disabled,
            true => Sr::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Sr::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Sr::Enabled
    }
}
#[doc = "Field `sr` writer - When this bit is set, the Receive process is placed in the Running state. The DMA attempts to acquire the descriptor from the Receive list and processes the incoming frames. The descriptor acquisition is attempted from the current position in the list, which is the address set by Register 3 (Receive Descriptor List Address Register) or the position retained when the Receive process was previously stopped. If the DMA does not own the descriptor, reception is suspended and Bit 7 (Receive Buffer Unavailable) of Register 5 (Status Register) is set. The Start Receive command is effective only when the reception has stopped. If the command is issued before setting Register 3 (Receive Descriptor List Address Register), the DMA behavior is unpredictable. When this bit is cleared, the Rx DMA operation is stopped after the transfer of the current frame. The next descriptor position in the Receive list is saved and becomes the current position after the Receive process is restarted. The Stop Receive command is effective only when the Receive process is in either the Running (waiting for receive packet) or in the Suspended state."]
pub type SrW<'a, REG> = crate::BitWriter<'a, REG, Sr>;
impl<'a, REG> SrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sr::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sr::Enabled)
    }
}
#[doc = "When this bit is set, it instructs the DMA to process the second frame of the Transmit data even before the status for the first frame is obtained.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Osf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Osf> for bool {
    #[inline(always)]
    fn from(variant: Osf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `osf` reader - When this bit is set, it instructs the DMA to process the second frame of the Transmit data even before the status for the first frame is obtained."]
pub type OsfR = crate::BitReader<Osf>;
impl OsfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Osf {
        match self.bits {
            false => Osf::Disabled,
            true => Osf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Osf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Osf::Enabled
    }
}
#[doc = "Field `osf` writer - When this bit is set, it instructs the DMA to process the second frame of the Transmit data even before the status for the first frame is obtained."]
pub type OsfW<'a, REG> = crate::BitWriter<'a, REG, Osf>;
impl<'a, REG> OsfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Osf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Osf::Enabled)
    }
}
#[doc = "These two bits control the threshold level of the MTL Receive FIFO. Transfer (request) to DMA starts when the frame size within the MTL Receive FIFO is larger than the threshold. In addition, full frames with length less than the threshold are transferred automatically. These bits are valid only when the RSF bit is zero, and are ignored when the RSF bit is set to 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rtc {
    #[doc = "0: `0`"]
    Thrfifo64 = 0,
    #[doc = "1: `1`"]
    Thrfifo32 = 1,
    #[doc = "2: `10`"]
    Thrfifo96 = 2,
    #[doc = "3: `11`"]
    Thrfifo128 = 3,
}
impl From<Rtc> for u8 {
    #[inline(always)]
    fn from(variant: Rtc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rtc {
    type Ux = u8;
}
#[doc = "Field `rtc` reader - These two bits control the threshold level of the MTL Receive FIFO. Transfer (request) to DMA starts when the frame size within the MTL Receive FIFO is larger than the threshold. In addition, full frames with length less than the threshold are transferred automatically. These bits are valid only when the RSF bit is zero, and are ignored when the RSF bit is set to 1."]
pub type RtcR = crate::FieldReader<Rtc>;
impl RtcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rtc {
        match self.bits {
            0 => Rtc::Thrfifo64,
            1 => Rtc::Thrfifo32,
            2 => Rtc::Thrfifo96,
            3 => Rtc::Thrfifo128,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_thrfifo64(&self) -> bool {
        *self == Rtc::Thrfifo64
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_thrfifo32(&self) -> bool {
        *self == Rtc::Thrfifo32
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_thrfifo96(&self) -> bool {
        *self == Rtc::Thrfifo96
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_thrfifo128(&self) -> bool {
        *self == Rtc::Thrfifo128
    }
}
#[doc = "Field `rtc` writer - These two bits control the threshold level of the MTL Receive FIFO. Transfer (request) to DMA starts when the frame size within the MTL Receive FIFO is larger than the threshold. In addition, full frames with length less than the threshold are transferred automatically. These bits are valid only when the RSF bit is zero, and are ignored when the RSF bit is set to 1."]
pub type RtcW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Rtc>;
impl<'a, REG> RtcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn thrfifo64(self) -> &'a mut crate::W<REG> {
        self.variant(Rtc::Thrfifo64)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn thrfifo32(self) -> &'a mut crate::W<REG> {
        self.variant(Rtc::Thrfifo32)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn thrfifo96(self) -> &'a mut crate::W<REG> {
        self.variant(Rtc::Thrfifo96)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn thrfifo128(self) -> &'a mut crate::W<REG> {
        self.variant(Rtc::Thrfifo128)
    }
}
#[doc = "When set, the Rx FIFO forwards Undersized frames (frames with no Error and length less than 64 bytes) including pad-bytes and CRC. When reset, the Rx FIFO drops all frames of less than 64 bytes, unless a frame is already transferred because of the lower value of Receive Threshold, for example, RTC = 01.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fuf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Fuf> for bool {
    #[inline(always)]
    fn from(variant: Fuf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fuf` reader - When set, the Rx FIFO forwards Undersized frames (frames with no Error and length less than 64 bytes) including pad-bytes and CRC. When reset, the Rx FIFO drops all frames of less than 64 bytes, unless a frame is already transferred because of the lower value of Receive Threshold, for example, RTC = 01."]
pub type FufR = crate::BitReader<Fuf>;
impl FufR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fuf {
        match self.bits {
            false => Fuf::Disabled,
            true => Fuf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Fuf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Fuf::Enabled
    }
}
#[doc = "Field `fuf` writer - When set, the Rx FIFO forwards Undersized frames (frames with no Error and length less than 64 bytes) including pad-bytes and CRC. When reset, the Rx FIFO drops all frames of less than 64 bytes, unless a frame is already transferred because of the lower value of Receive Threshold, for example, RTC = 01."]
pub type FufW<'a, REG> = crate::BitWriter<'a, REG, Fuf>;
impl<'a, REG> FufW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fuf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fuf::Enabled)
    }
}
#[doc = "When this bit is reset, the Rx FIFO drops frames with error status (CRC error, collision error, GMII_ER, giant frame, watchdog timeout, or overflow). However, if the start byte (write) pointer of a frame is already transferred to the read controller side (in Threshold mode), then the frame is not dropped. When the FEF bit is set, all frames except runt error frames are forwarded to the DMA. If the Bit 25 (RSF) is set and the Rx FIFO overflows when a partial frame is written, then the frame is dropped irrespective of the FEF bit setting. However, if the Bit 25 (RSF) is reset and the Rx FIFO overflows when a partial frame is written, then a partial frame may be forwarded to the DMA.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fef {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Fef> for bool {
    #[inline(always)]
    fn from(variant: Fef) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fef` reader - When this bit is reset, the Rx FIFO drops frames with error status (CRC error, collision error, GMII_ER, giant frame, watchdog timeout, or overflow). However, if the start byte (write) pointer of a frame is already transferred to the read controller side (in Threshold mode), then the frame is not dropped. When the FEF bit is set, all frames except runt error frames are forwarded to the DMA. If the Bit 25 (RSF) is set and the Rx FIFO overflows when a partial frame is written, then the frame is dropped irrespective of the FEF bit setting. However, if the Bit 25 (RSF) is reset and the Rx FIFO overflows when a partial frame is written, then a partial frame may be forwarded to the DMA."]
pub type FefR = crate::BitReader<Fef>;
impl FefR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fef {
        match self.bits {
            false => Fef::Disabled,
            true => Fef::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Fef::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Fef::Enabled
    }
}
#[doc = "Field `fef` writer - When this bit is reset, the Rx FIFO drops frames with error status (CRC error, collision error, GMII_ER, giant frame, watchdog timeout, or overflow). However, if the start byte (write) pointer of a frame is already transferred to the read controller side (in Threshold mode), then the frame is not dropped. When the FEF bit is set, all frames except runt error frames are forwarded to the DMA. If the Bit 25 (RSF) is set and the Rx FIFO overflows when a partial frame is written, then the frame is dropped irrespective of the FEF bit setting. However, if the Bit 25 (RSF) is reset and the Rx FIFO overflows when a partial frame is written, then a partial frame may be forwarded to the DMA."]
pub type FefW<'a, REG> = crate::BitWriter<'a, REG, Fef>;
impl<'a, REG> FefW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fef::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fef::Enabled)
    }
}
#[doc = "When this bit is set, the flow control signal operation based on the fill-level of Rx FIFO is enabled. When reset, the flow control operation is disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Efc {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Efc> for bool {
    #[inline(always)]
    fn from(variant: Efc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `efc` reader - When this bit is set, the flow control signal operation based on the fill-level of Rx FIFO is enabled. When reset, the flow control operation is disabled."]
pub type EfcR = crate::BitReader<Efc>;
impl EfcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Efc {
        match self.bits {
            false => Efc::Disabled,
            true => Efc::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Efc::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Efc::Enabled
    }
}
#[doc = "Field `efc` writer - When this bit is set, the flow control signal operation based on the fill-level of Rx FIFO is enabled. When reset, the flow control operation is disabled."]
pub type EfcW<'a, REG> = crate::BitWriter<'a, REG, Efc>;
impl<'a, REG> EfcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Efc::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Efc::Enabled)
    }
}
#[doc = "These bits control the threshold (Fill level of Rx FIFO) at which the flow control is activated. These values only apply to the Rx FIFO when the EFC bit is set high.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rfa {
    #[doc = "0: `0`"]
    Fifofull1k = 0,
    #[doc = "1: `1`"]
    Fifofull2k = 1,
    #[doc = "2: `10`"]
    Fifofull3k = 2,
    #[doc = "3: `11`"]
    Fifofull4k = 3,
}
impl From<Rfa> for u8 {
    #[inline(always)]
    fn from(variant: Rfa) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rfa {
    type Ux = u8;
}
#[doc = "Field `rfa` reader - These bits control the threshold (Fill level of Rx FIFO) at which the flow control is activated. These values only apply to the Rx FIFO when the EFC bit is set high."]
pub type RfaR = crate::FieldReader<Rfa>;
impl RfaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rfa {
        match self.bits {
            0 => Rfa::Fifofull1k,
            1 => Rfa::Fifofull2k,
            2 => Rfa::Fifofull3k,
            3 => Rfa::Fifofull4k,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fifofull_1k(&self) -> bool {
        *self == Rfa::Fifofull1k
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fifofull_2k(&self) -> bool {
        *self == Rfa::Fifofull2k
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_fifofull_3k(&self) -> bool {
        *self == Rfa::Fifofull3k
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_fifofull_4k(&self) -> bool {
        *self == Rfa::Fifofull4k
    }
}
#[doc = "Field `rfa` writer - These bits control the threshold (Fill level of Rx FIFO) at which the flow control is activated. These values only apply to the Rx FIFO when the EFC bit is set high."]
pub type RfaW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Rfa>;
impl<'a, REG> RfaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fifofull_1k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfa::Fifofull1k)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fifofull_2k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfa::Fifofull2k)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn fifofull_3k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfa::Fifofull3k)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn fifofull_4k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfa::Fifofull4k)
    }
}
#[doc = "These bits control the threshold (Fill-level of Rx FIFO) at which the flow control is de-asserted after activation. The de-assertion is effective only after flow control is asserted.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rfd {
    #[doc = "0: `0`"]
    Fifofull1k = 0,
    #[doc = "1: `1`"]
    Fifofull2k = 1,
    #[doc = "2: `10`"]
    Fifofull3k = 2,
    #[doc = "3: `11`"]
    Fifofull4k = 3,
}
impl From<Rfd> for u8 {
    #[inline(always)]
    fn from(variant: Rfd) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rfd {
    type Ux = u8;
}
#[doc = "Field `rfd` reader - These bits control the threshold (Fill-level of Rx FIFO) at which the flow control is de-asserted after activation. The de-assertion is effective only after flow control is asserted."]
pub type RfdR = crate::FieldReader<Rfd>;
impl RfdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rfd {
        match self.bits {
            0 => Rfd::Fifofull1k,
            1 => Rfd::Fifofull2k,
            2 => Rfd::Fifofull3k,
            3 => Rfd::Fifofull4k,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fifofull_1k(&self) -> bool {
        *self == Rfd::Fifofull1k
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fifofull_2k(&self) -> bool {
        *self == Rfd::Fifofull2k
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_fifofull_3k(&self) -> bool {
        *self == Rfd::Fifofull3k
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_fifofull_4k(&self) -> bool {
        *self == Rfd::Fifofull4k
    }
}
#[doc = "Field `rfd` writer - These bits control the threshold (Fill-level of Rx FIFO) at which the flow control is de-asserted after activation. The de-assertion is effective only after flow control is asserted."]
pub type RfdW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Rfd>;
impl<'a, REG> RfdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fifofull_1k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfd::Fifofull1k)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fifofull_2k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfd::Fifofull2k)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn fifofull_3k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfd::Fifofull3k)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn fifofull_4k(self) -> &'a mut crate::W<REG> {
        self.variant(Rfd::Fifofull4k)
    }
}
#[doc = "When this bit is set, transmission is placed in the Running state, and the DMA checks the Transmit List at the current position for a frame to be transmitted. Descriptor acquisition is attempted either from the current position in the list, which is the Transmit List Base Address set by Register 4 (Transmit Descriptor List Address Register), or from the position retained when transmission was stopped previously. If the DMA does not own the current descriptor, transmission enters the Suspended state and Bit 2 (Transmit Buffer Unavailable) of Register 5 (Status Register) is set. The Start Transmission command is effective only when transmission is stopped. If the command is issued before setting Register 4 (Transmit Descriptor List Address Register), then the DMA behavior is unpredictable. When this bit is reset, the transmission process is placed in the Stopped state after completing the transmission of the current frame. The Next Descriptor position in the Transmit List is saved, and it becomes the current position when transmission is restarted. To change the list address, you need to program Register 4 (Transmit Descriptor List Address Register) with a new value when this bit is reset. The new value is considered when this bit is set again. The stop transmission command is effective only when the transmission of the current frame is complete or the transmission is in the Suspended state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum St {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<St> for bool {
    #[inline(always)]
    fn from(variant: St) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `st` reader - When this bit is set, transmission is placed in the Running state, and the DMA checks the Transmit List at the current position for a frame to be transmitted. Descriptor acquisition is attempted either from the current position in the list, which is the Transmit List Base Address set by Register 4 (Transmit Descriptor List Address Register), or from the position retained when transmission was stopped previously. If the DMA does not own the current descriptor, transmission enters the Suspended state and Bit 2 (Transmit Buffer Unavailable) of Register 5 (Status Register) is set. The Start Transmission command is effective only when transmission is stopped. If the command is issued before setting Register 4 (Transmit Descriptor List Address Register), then the DMA behavior is unpredictable. When this bit is reset, the transmission process is placed in the Stopped state after completing the transmission of the current frame. The Next Descriptor position in the Transmit List is saved, and it becomes the current position when transmission is restarted. To change the list address, you need to program Register 4 (Transmit Descriptor List Address Register) with a new value when this bit is reset. The new value is considered when this bit is set again. The stop transmission command is effective only when the transmission of the current frame is complete or the transmission is in the Suspended state."]
pub type StR = crate::BitReader<St>;
impl StR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> St {
        match self.bits {
            false => St::Disabled,
            true => St::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == St::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == St::Enabled
    }
}
#[doc = "Field `st` writer - When this bit is set, transmission is placed in the Running state, and the DMA checks the Transmit List at the current position for a frame to be transmitted. Descriptor acquisition is attempted either from the current position in the list, which is the Transmit List Base Address set by Register 4 (Transmit Descriptor List Address Register), or from the position retained when transmission was stopped previously. If the DMA does not own the current descriptor, transmission enters the Suspended state and Bit 2 (Transmit Buffer Unavailable) of Register 5 (Status Register) is set. The Start Transmission command is effective only when transmission is stopped. If the command is issued before setting Register 4 (Transmit Descriptor List Address Register), then the DMA behavior is unpredictable. When this bit is reset, the transmission process is placed in the Stopped state after completing the transmission of the current frame. The Next Descriptor position in the Transmit List is saved, and it becomes the current position when transmission is restarted. To change the list address, you need to program Register 4 (Transmit Descriptor List Address Register) with a new value when this bit is reset. The new value is considered when this bit is set again. The stop transmission command is effective only when the transmission of the current frame is complete or the transmission is in the Suspended state."]
pub type StW<'a, REG> = crate::BitWriter<'a, REG, St>;
impl<'a, REG> StW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(St::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(St::Enabled)
    }
}
#[doc = "These bits control the threshold level of the MTL Transmit FIFO. Transmission starts when the frame size within the MTL Transmit FIFO is larger than the threshold. In addition, full frames with a length less than the threshold are also transmitted. These bits are used only when Bit 21 (TSF) is reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ttc {
    #[doc = "0: `0`"]
    Ttcthesh64 = 0,
    #[doc = "1: `1`"]
    Ttcthres128 = 1,
    #[doc = "2: `10`"]
    Ttcthres192 = 2,
    #[doc = "3: `11`"]
    Ttcthres256 = 3,
    #[doc = "4: `100`"]
    Ttcthres40 = 4,
    #[doc = "5: `101`"]
    Ttcthres32 = 5,
    #[doc = "6: `110`"]
    Ttcthres24 = 6,
    #[doc = "7: `111`"]
    Ttcthres16 = 7,
}
impl From<Ttc> for u8 {
    #[inline(always)]
    fn from(variant: Ttc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ttc {
    type Ux = u8;
}
#[doc = "Field `ttc` reader - These bits control the threshold level of the MTL Transmit FIFO. Transmission starts when the frame size within the MTL Transmit FIFO is larger than the threshold. In addition, full frames with a length less than the threshold are also transmitted. These bits are used only when Bit 21 (TSF) is reset."]
pub type TtcR = crate::FieldReader<Ttc>;
impl TtcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ttc {
        match self.bits {
            0 => Ttc::Ttcthesh64,
            1 => Ttc::Ttcthres128,
            2 => Ttc::Ttcthres192,
            3 => Ttc::Ttcthres256,
            4 => Ttc::Ttcthres40,
            5 => Ttc::Ttcthres32,
            6 => Ttc::Ttcthres24,
            7 => Ttc::Ttcthres16,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ttcthesh64(&self) -> bool {
        *self == Ttc::Ttcthesh64
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ttcthres128(&self) -> bool {
        *self == Ttc::Ttcthres128
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_ttcthres192(&self) -> bool {
        *self == Ttc::Ttcthres192
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_ttcthres256(&self) -> bool {
        *self == Ttc::Ttcthres256
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_ttcthres40(&self) -> bool {
        *self == Ttc::Ttcthres40
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_ttcthres32(&self) -> bool {
        *self == Ttc::Ttcthres32
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_ttcthres24(&self) -> bool {
        *self == Ttc::Ttcthres24
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_ttcthres16(&self) -> bool {
        *self == Ttc::Ttcthres16
    }
}
#[doc = "Field `ttc` writer - These bits control the threshold level of the MTL Transmit FIFO. Transmission starts when the frame size within the MTL Transmit FIFO is larger than the threshold. In addition, full frames with a length less than the threshold are also transmitted. These bits are used only when Bit 21 (TSF) is reset."]
pub type TtcW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Ttc>;
impl<'a, REG> TtcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ttcthesh64(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthesh64)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ttcthres128(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres128)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn ttcthres192(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres192)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn ttcthres256(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres256)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn ttcthres40(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres40)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn ttcthres32(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres32)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn ttcthres24(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres24)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn ttcthres16(self) -> &'a mut crate::W<REG> {
        self.variant(Ttc::Ttcthres16)
    }
}
#[doc = "When this bit is set, the transmit FIFO controller logic is reset to its default values and thus all data in the Tx FIFO is lost or flushed. This bit is cleared internally when the flushing operation is completed. The Operation Mode register should not be written to until this bit is cleared. The data which is already accepted by the MAC transmitter is not flushed. It is scheduled for transmission and results in underflow and runt frame transmission. Note: The flush operation is complete only when the Tx FIFO is emptied of its contents and all the pending Transmit Status of the transmitted frames are accepted by the host. To complete this flush operation, the PHY transmit clock is required to be active.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ftf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ftf> for bool {
    #[inline(always)]
    fn from(variant: Ftf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ftf` reader - When this bit is set, the transmit FIFO controller logic is reset to its default values and thus all data in the Tx FIFO is lost or flushed. This bit is cleared internally when the flushing operation is completed. The Operation Mode register should not be written to until this bit is cleared. The data which is already accepted by the MAC transmitter is not flushed. It is scheduled for transmission and results in underflow and runt frame transmission. Note: The flush operation is complete only when the Tx FIFO is emptied of its contents and all the pending Transmit Status of the transmitted frames are accepted by the host. To complete this flush operation, the PHY transmit clock is required to be active."]
pub type FtfR = crate::BitReader<Ftf>;
impl FtfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ftf {
        match self.bits {
            false => Ftf::Disabled,
            true => Ftf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ftf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ftf::Enabled
    }
}
#[doc = "Field `ftf` writer - When this bit is set, the transmit FIFO controller logic is reset to its default values and thus all data in the Tx FIFO is lost or flushed. This bit is cleared internally when the flushing operation is completed. The Operation Mode register should not be written to until this bit is cleared. The data which is already accepted by the MAC transmitter is not flushed. It is scheduled for transmission and results in underflow and runt frame transmission. Note: The flush operation is complete only when the Tx FIFO is emptied of its contents and all the pending Transmit Status of the transmitted frames are accepted by the host. To complete this flush operation, the PHY transmit clock is required to be active."]
pub type FtfW<'a, REG> = crate::BitWriter<'a, REG, Ftf>;
impl<'a, REG> FtfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ftf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ftf::Enabled)
    }
}
#[doc = "When this bit is set, transmission starts when a full frame resides in the MTL Transmit FIFO. When this bit is set, the TTC values specified in Bits\\[16:14\\]
are ignored. This bit should be changed only when the transmission is stopped.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsf> for bool {
    #[inline(always)]
    fn from(variant: Tsf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsf` reader - When this bit is set, transmission starts when a full frame resides in the MTL Transmit FIFO. When this bit is set, the TTC values specified in Bits\\[16:14\\]
are ignored. This bit should be changed only when the transmission is stopped."]
pub type TsfR = crate::BitReader<Tsf>;
impl TsfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsf {
        match self.bits {
            false => Tsf::Disabled,
            true => Tsf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsf::Enabled
    }
}
#[doc = "Field `tsf` writer - When this bit is set, transmission starts when a full frame resides in the MTL Transmit FIFO. When this bit is set, the TTC values specified in Bits\\[16:14\\]
are ignored. This bit should be changed only when the transmission is stopped."]
pub type TsfW<'a, REG> = crate::BitWriter<'a, REG, Tsf>;
impl<'a, REG> TsfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsf::Enabled)
    }
}
#[doc = "When this bit is set, the Rx DMA does not flush any frames because of the unavailability of receive descriptors or buffers as it does normally when this bit is reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dff {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dff> for bool {
    #[inline(always)]
    fn from(variant: Dff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dff` reader - When this bit is set, the Rx DMA does not flush any frames because of the unavailability of receive descriptors or buffers as it does normally when this bit is reset."]
pub type DffR = crate::BitReader<Dff>;
impl DffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dff {
        match self.bits {
            false => Dff::Disabled,
            true => Dff::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dff::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dff::Enabled
    }
}
#[doc = "Field `dff` writer - When this bit is set, the Rx DMA does not flush any frames because of the unavailability of receive descriptors or buffers as it does normally when this bit is reset."]
pub type DffW<'a, REG> = crate::BitWriter<'a, REG, Dff>;
impl<'a, REG> DffW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dff::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dff::Enabled)
    }
}
#[doc = "When this bit is set, the MTL reads a frame from the Rx FIFO only after the complete frame has been written to it, ignoring the RTC bits. When this bit is reset, the Rx FIFO operates in the cut-through mode, subject to the threshold specified by the RTC bits.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rsf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rsf> for bool {
    #[inline(always)]
    fn from(variant: Rsf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rsf` reader - When this bit is set, the MTL reads a frame from the Rx FIFO only after the complete frame has been written to it, ignoring the RTC bits. When this bit is reset, the Rx FIFO operates in the cut-through mode, subject to the threshold specified by the RTC bits."]
pub type RsfR = crate::BitReader<Rsf>;
impl RsfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rsf {
        match self.bits {
            false => Rsf::Disabled,
            true => Rsf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rsf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rsf::Enabled
    }
}
#[doc = "Field `rsf` writer - When this bit is set, the MTL reads a frame from the Rx FIFO only after the complete frame has been written to it, ignoring the RTC bits. When this bit is reset, the Rx FIFO operates in the cut-through mode, subject to the threshold specified by the RTC bits."]
pub type RsfW<'a, REG> = crate::BitWriter<'a, REG, Rsf>;
impl<'a, REG> RsfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rsf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rsf::Enabled)
    }
}
#[doc = "When this bit is set, the MAC does not drop the frames which only have errors detected by the Receive Checksum Offload engine. Such frames do not have any errors (including FCS error) in the Ethernet frame received by the MAC but have errors only in the encapsulated payload. When this bit is reset, all error frames are dropped if the FEF bit is reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dt {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dt> for bool {
    #[inline(always)]
    fn from(variant: Dt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dt` reader - When this bit is set, the MAC does not drop the frames which only have errors detected by the Receive Checksum Offload engine. Such frames do not have any errors (including FCS error) in the Ethernet frame received by the MAC but have errors only in the encapsulated payload. When this bit is reset, all error frames are dropped if the FEF bit is reset."]
pub type DtR = crate::BitReader<Dt>;
impl DtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dt {
        match self.bits {
            false => Dt::Disabled,
            true => Dt::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dt::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dt::Enabled
    }
}
#[doc = "Field `dt` writer - When this bit is set, the MAC does not drop the frames which only have errors detected by the Receive Checksum Offload engine. Such frames do not have any errors (including FCS error) in the Ethernet frame received by the MAC but have errors only in the encapsulated payload. When this bit is reset, all error frames are dropped if the FEF bit is reset."]
pub type DtW<'a, REG> = crate::BitWriter<'a, REG, Dt>;
impl<'a, REG> DtW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dt::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dt::Enabled)
    }
}
impl R {
    #[doc = "Bit 1 - When this bit is set, the Receive process is placed in the Running state. The DMA attempts to acquire the descriptor from the Receive list and processes the incoming frames. The descriptor acquisition is attempted from the current position in the list, which is the address set by Register 3 (Receive Descriptor List Address Register) or the position retained when the Receive process was previously stopped. If the DMA does not own the descriptor, reception is suspended and Bit 7 (Receive Buffer Unavailable) of Register 5 (Status Register) is set. The Start Receive command is effective only when the reception has stopped. If the command is issued before setting Register 3 (Receive Descriptor List Address Register), the DMA behavior is unpredictable. When this bit is cleared, the Rx DMA operation is stopped after the transfer of the current frame. The next descriptor position in the Receive list is saved and becomes the current position after the Receive process is restarted. The Stop Receive command is effective only when the Receive process is in either the Running (waiting for receive packet) or in the Suspended state."]
    #[inline(always)]
    pub fn sr(&self) -> SrR {
        SrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When this bit is set, it instructs the DMA to process the second frame of the Transmit data even before the status for the first frame is obtained."]
    #[inline(always)]
    pub fn osf(&self) -> OsfR {
        OsfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:4 - These two bits control the threshold level of the MTL Receive FIFO. Transfer (request) to DMA starts when the frame size within the MTL Receive FIFO is larger than the threshold. In addition, full frames with length less than the threshold are transferred automatically. These bits are valid only when the RSF bit is zero, and are ignored when the RSF bit is set to 1."]
    #[inline(always)]
    pub fn rtc(&self) -> RtcR {
        RtcR::new(((self.bits >> 3) & 3) as u8)
    }
    #[doc = "Bit 6 - When set, the Rx FIFO forwards Undersized frames (frames with no Error and length less than 64 bytes) including pad-bytes and CRC. When reset, the Rx FIFO drops all frames of less than 64 bytes, unless a frame is already transferred because of the lower value of Receive Threshold, for example, RTC = 01."]
    #[inline(always)]
    pub fn fuf(&self) -> FufR {
        FufR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - When this bit is reset, the Rx FIFO drops frames with error status (CRC error, collision error, GMII_ER, giant frame, watchdog timeout, or overflow). However, if the start byte (write) pointer of a frame is already transferred to the read controller side (in Threshold mode), then the frame is not dropped. When the FEF bit is set, all frames except runt error frames are forwarded to the DMA. If the Bit 25 (RSF) is set and the Rx FIFO overflows when a partial frame is written, then the frame is dropped irrespective of the FEF bit setting. However, if the Bit 25 (RSF) is reset and the Rx FIFO overflows when a partial frame is written, then a partial frame may be forwarded to the DMA."]
    #[inline(always)]
    pub fn fef(&self) -> FefR {
        FefR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - When this bit is set, the flow control signal operation based on the fill-level of Rx FIFO is enabled. When reset, the flow control operation is disabled."]
    #[inline(always)]
    pub fn efc(&self) -> EfcR {
        EfcR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bits 9:10 - These bits control the threshold (Fill level of Rx FIFO) at which the flow control is activated. These values only apply to the Rx FIFO when the EFC bit is set high."]
    #[inline(always)]
    pub fn rfa(&self) -> RfaR {
        RfaR::new(((self.bits >> 9) & 3) as u8)
    }
    #[doc = "Bits 11:12 - These bits control the threshold (Fill-level of Rx FIFO) at which the flow control is de-asserted after activation. The de-assertion is effective only after flow control is asserted."]
    #[inline(always)]
    pub fn rfd(&self) -> RfdR {
        RfdR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bit 13 - When this bit is set, transmission is placed in the Running state, and the DMA checks the Transmit List at the current position for a frame to be transmitted. Descriptor acquisition is attempted either from the current position in the list, which is the Transmit List Base Address set by Register 4 (Transmit Descriptor List Address Register), or from the position retained when transmission was stopped previously. If the DMA does not own the current descriptor, transmission enters the Suspended state and Bit 2 (Transmit Buffer Unavailable) of Register 5 (Status Register) is set. The Start Transmission command is effective only when transmission is stopped. If the command is issued before setting Register 4 (Transmit Descriptor List Address Register), then the DMA behavior is unpredictable. When this bit is reset, the transmission process is placed in the Stopped state after completing the transmission of the current frame. The Next Descriptor position in the Transmit List is saved, and it becomes the current position when transmission is restarted. To change the list address, you need to program Register 4 (Transmit Descriptor List Address Register) with a new value when this bit is reset. The new value is considered when this bit is set again. The stop transmission command is effective only when the transmission of the current frame is complete or the transmission is in the Suspended state."]
    #[inline(always)]
    pub fn st(&self) -> StR {
        StR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 14:16 - These bits control the threshold level of the MTL Transmit FIFO. Transmission starts when the frame size within the MTL Transmit FIFO is larger than the threshold. In addition, full frames with a length less than the threshold are also transmitted. These bits are used only when Bit 21 (TSF) is reset."]
    #[inline(always)]
    pub fn ttc(&self) -> TtcR {
        TtcR::new(((self.bits >> 14) & 7) as u8)
    }
    #[doc = "Bit 20 - When this bit is set, the transmit FIFO controller logic is reset to its default values and thus all data in the Tx FIFO is lost or flushed. This bit is cleared internally when the flushing operation is completed. The Operation Mode register should not be written to until this bit is cleared. The data which is already accepted by the MAC transmitter is not flushed. It is scheduled for transmission and results in underflow and runt frame transmission. Note: The flush operation is complete only when the Tx FIFO is emptied of its contents and all the pending Transmit Status of the transmitted frames are accepted by the host. To complete this flush operation, the PHY transmit clock is required to be active."]
    #[inline(always)]
    pub fn ftf(&self) -> FtfR {
        FtfR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - When this bit is set, transmission starts when a full frame resides in the MTL Transmit FIFO. When this bit is set, the TTC values specified in Bits\\[16:14\\]
are ignored. This bit should be changed only when the transmission is stopped."]
    #[inline(always)]
    pub fn tsf(&self) -> TsfR {
        TsfR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 24 - When this bit is set, the Rx DMA does not flush any frames because of the unavailability of receive descriptors or buffers as it does normally when this bit is reset."]
    #[inline(always)]
    pub fn dff(&self) -> DffR {
        DffR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - When this bit is set, the MTL reads a frame from the Rx FIFO only after the complete frame has been written to it, ignoring the RTC bits. When this bit is reset, the Rx FIFO operates in the cut-through mode, subject to the threshold specified by the RTC bits."]
    #[inline(always)]
    pub fn rsf(&self) -> RsfR {
        RsfR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - When this bit is set, the MAC does not drop the frames which only have errors detected by the Receive Checksum Offload engine. Such frames do not have any errors (including FCS error) in the Ethernet frame received by the MAC but have errors only in the encapsulated payload. When this bit is reset, all error frames are dropped if the FEF bit is reset."]
    #[inline(always)]
    pub fn dt(&self) -> DtR {
        DtR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - When this bit is set, the Receive process is placed in the Running state. The DMA attempts to acquire the descriptor from the Receive list and processes the incoming frames. The descriptor acquisition is attempted from the current position in the list, which is the address set by Register 3 (Receive Descriptor List Address Register) or the position retained when the Receive process was previously stopped. If the DMA does not own the descriptor, reception is suspended and Bit 7 (Receive Buffer Unavailable) of Register 5 (Status Register) is set. The Start Receive command is effective only when the reception has stopped. If the command is issued before setting Register 3 (Receive Descriptor List Address Register), the DMA behavior is unpredictable. When this bit is cleared, the Rx DMA operation is stopped after the transfer of the current frame. The next descriptor position in the Receive list is saved and becomes the current position after the Receive process is restarted. The Stop Receive command is effective only when the Receive process is in either the Running (waiting for receive packet) or in the Suspended state."]
    #[inline(always)]
    #[must_use]
    pub fn sr(&mut self) -> SrW<DmagrpOperationModeSpec> {
        SrW::new(self, 1)
    }
    #[doc = "Bit 2 - When this bit is set, it instructs the DMA to process the second frame of the Transmit data even before the status for the first frame is obtained."]
    #[inline(always)]
    #[must_use]
    pub fn osf(&mut self) -> OsfW<DmagrpOperationModeSpec> {
        OsfW::new(self, 2)
    }
    #[doc = "Bits 3:4 - These two bits control the threshold level of the MTL Receive FIFO. Transfer (request) to DMA starts when the frame size within the MTL Receive FIFO is larger than the threshold. In addition, full frames with length less than the threshold are transferred automatically. These bits are valid only when the RSF bit is zero, and are ignored when the RSF bit is set to 1."]
    #[inline(always)]
    #[must_use]
    pub fn rtc(&mut self) -> RtcW<DmagrpOperationModeSpec> {
        RtcW::new(self, 3)
    }
    #[doc = "Bit 6 - When set, the Rx FIFO forwards Undersized frames (frames with no Error and length less than 64 bytes) including pad-bytes and CRC. When reset, the Rx FIFO drops all frames of less than 64 bytes, unless a frame is already transferred because of the lower value of Receive Threshold, for example, RTC = 01."]
    #[inline(always)]
    #[must_use]
    pub fn fuf(&mut self) -> FufW<DmagrpOperationModeSpec> {
        FufW::new(self, 6)
    }
    #[doc = "Bit 7 - When this bit is reset, the Rx FIFO drops frames with error status (CRC error, collision error, GMII_ER, giant frame, watchdog timeout, or overflow). However, if the start byte (write) pointer of a frame is already transferred to the read controller side (in Threshold mode), then the frame is not dropped. When the FEF bit is set, all frames except runt error frames are forwarded to the DMA. If the Bit 25 (RSF) is set and the Rx FIFO overflows when a partial frame is written, then the frame is dropped irrespective of the FEF bit setting. However, if the Bit 25 (RSF) is reset and the Rx FIFO overflows when a partial frame is written, then a partial frame may be forwarded to the DMA."]
    #[inline(always)]
    #[must_use]
    pub fn fef(&mut self) -> FefW<DmagrpOperationModeSpec> {
        FefW::new(self, 7)
    }
    #[doc = "Bit 8 - When this bit is set, the flow control signal operation based on the fill-level of Rx FIFO is enabled. When reset, the flow control operation is disabled."]
    #[inline(always)]
    #[must_use]
    pub fn efc(&mut self) -> EfcW<DmagrpOperationModeSpec> {
        EfcW::new(self, 8)
    }
    #[doc = "Bits 9:10 - These bits control the threshold (Fill level of Rx FIFO) at which the flow control is activated. These values only apply to the Rx FIFO when the EFC bit is set high."]
    #[inline(always)]
    #[must_use]
    pub fn rfa(&mut self) -> RfaW<DmagrpOperationModeSpec> {
        RfaW::new(self, 9)
    }
    #[doc = "Bits 11:12 - These bits control the threshold (Fill-level of Rx FIFO) at which the flow control is de-asserted after activation. The de-assertion is effective only after flow control is asserted."]
    #[inline(always)]
    #[must_use]
    pub fn rfd(&mut self) -> RfdW<DmagrpOperationModeSpec> {
        RfdW::new(self, 11)
    }
    #[doc = "Bit 13 - When this bit is set, transmission is placed in the Running state, and the DMA checks the Transmit List at the current position for a frame to be transmitted. Descriptor acquisition is attempted either from the current position in the list, which is the Transmit List Base Address set by Register 4 (Transmit Descriptor List Address Register), or from the position retained when transmission was stopped previously. If the DMA does not own the current descriptor, transmission enters the Suspended state and Bit 2 (Transmit Buffer Unavailable) of Register 5 (Status Register) is set. The Start Transmission command is effective only when transmission is stopped. If the command is issued before setting Register 4 (Transmit Descriptor List Address Register), then the DMA behavior is unpredictable. When this bit is reset, the transmission process is placed in the Stopped state after completing the transmission of the current frame. The Next Descriptor position in the Transmit List is saved, and it becomes the current position when transmission is restarted. To change the list address, you need to program Register 4 (Transmit Descriptor List Address Register) with a new value when this bit is reset. The new value is considered when this bit is set again. The stop transmission command is effective only when the transmission of the current frame is complete or the transmission is in the Suspended state."]
    #[inline(always)]
    #[must_use]
    pub fn st(&mut self) -> StW<DmagrpOperationModeSpec> {
        StW::new(self, 13)
    }
    #[doc = "Bits 14:16 - These bits control the threshold level of the MTL Transmit FIFO. Transmission starts when the frame size within the MTL Transmit FIFO is larger than the threshold. In addition, full frames with a length less than the threshold are also transmitted. These bits are used only when Bit 21 (TSF) is reset."]
    #[inline(always)]
    #[must_use]
    pub fn ttc(&mut self) -> TtcW<DmagrpOperationModeSpec> {
        TtcW::new(self, 14)
    }
    #[doc = "Bit 20 - When this bit is set, the transmit FIFO controller logic is reset to its default values and thus all data in the Tx FIFO is lost or flushed. This bit is cleared internally when the flushing operation is completed. The Operation Mode register should not be written to until this bit is cleared. The data which is already accepted by the MAC transmitter is not flushed. It is scheduled for transmission and results in underflow and runt frame transmission. Note: The flush operation is complete only when the Tx FIFO is emptied of its contents and all the pending Transmit Status of the transmitted frames are accepted by the host. To complete this flush operation, the PHY transmit clock is required to be active."]
    #[inline(always)]
    #[must_use]
    pub fn ftf(&mut self) -> FtfW<DmagrpOperationModeSpec> {
        FtfW::new(self, 20)
    }
    #[doc = "Bit 21 - When this bit is set, transmission starts when a full frame resides in the MTL Transmit FIFO. When this bit is set, the TTC values specified in Bits\\[16:14\\]
are ignored. This bit should be changed only when the transmission is stopped."]
    #[inline(always)]
    #[must_use]
    pub fn tsf(&mut self) -> TsfW<DmagrpOperationModeSpec> {
        TsfW::new(self, 21)
    }
    #[doc = "Bit 24 - When this bit is set, the Rx DMA does not flush any frames because of the unavailability of receive descriptors or buffers as it does normally when this bit is reset."]
    #[inline(always)]
    #[must_use]
    pub fn dff(&mut self) -> DffW<DmagrpOperationModeSpec> {
        DffW::new(self, 24)
    }
    #[doc = "Bit 25 - When this bit is set, the MTL reads a frame from the Rx FIFO only after the complete frame has been written to it, ignoring the RTC bits. When this bit is reset, the Rx FIFO operates in the cut-through mode, subject to the threshold specified by the RTC bits."]
    #[inline(always)]
    #[must_use]
    pub fn rsf(&mut self) -> RsfW<DmagrpOperationModeSpec> {
        RsfW::new(self, 25)
    }
    #[doc = "Bit 26 - When this bit is set, the MAC does not drop the frames which only have errors detected by the Receive Checksum Offload engine. Such frames do not have any errors (including FCS error) in the Ethernet frame received by the MAC but have errors only in the encapsulated payload. When this bit is reset, all error frames are dropped if the FEF bit is reset."]
    #[inline(always)]
    #[must_use]
    pub fn dt(&mut self) -> DtW<DmagrpOperationModeSpec> {
        DtW::new(self, 26)
    }
}
#[doc = "The Operation Mode register establishes the Transmit and Receive operating modes and commands. This register should be the last CSR to be written as part of the DMA initialization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_operation_mode::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_operation_mode::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpOperationModeSpec;
impl crate::RegisterSpec for DmagrpOperationModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 4120u64;
}
#[doc = "`read()` method returns [`dmagrp_operation_mode::R`](R) reader structure"]
impl crate::Readable for DmagrpOperationModeSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_operation_mode::W`](W) writer structure"]
impl crate::Writable for DmagrpOperationModeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Operation_Mode to value 0"]
impl crate::Resettable for DmagrpOperationModeSpec {
    const RESET_VALUE: u32 = 0;
}
