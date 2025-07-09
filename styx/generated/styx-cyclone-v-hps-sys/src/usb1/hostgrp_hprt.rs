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
#[doc = "Register `hostgrp_hprt` reader"]
pub type R = crate::R<HostgrpHprtSpec>;
#[doc = "Register `hostgrp_hprt` writer"]
pub type W = crate::W<HostgrpHprtSpec>;
#[doc = "Defines whether port is attached.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtconnsts {
    #[doc = "0: `0`"]
    Notattached = 0,
    #[doc = "1: `1`"]
    Attached = 1,
}
impl From<Prtconnsts> for bool {
    #[inline(always)]
    fn from(variant: Prtconnsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtconnsts` reader - Defines whether port is attached."]
pub type PrtconnstsR = crate::BitReader<Prtconnsts>;
impl PrtconnstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtconnsts {
        match self.bits {
            false => Prtconnsts::Notattached,
            true => Prtconnsts::Attached,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notattached(&self) -> bool {
        *self == Prtconnsts::Notattached
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_attached(&self) -> bool {
        *self == Prtconnsts::Attached
    }
}
#[doc = "Field `prtconnsts` writer - Defines whether port is attached."]
pub type PrtconnstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core sets this bit when a device connection is detected to trigger an interrupt to the application using the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). This bit can be set only by the core and the application should write 1 to clear it.The application must write a 1 to this bit to clear the interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrtConnDet {
    #[doc = "0: `0`"]
    Active = 0,
    #[doc = "1: `1`"]
    Inactive = 1,
}
impl From<PrtConnDet> for bool {
    #[inline(always)]
    fn from(variant: PrtConnDet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `PrtConnDet` reader - The core sets this bit when a device connection is detected to trigger an interrupt to the application using the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). This bit can be set only by the core and the application should write 1 to clear it.The application must write a 1 to this bit to clear the interrupt."]
pub type PrtConnDetR = crate::BitReader<PrtConnDet>;
impl PrtConnDetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> PrtConnDet {
        match self.bits {
            false => PrtConnDet::Active,
            true => PrtConnDet::Inactive,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == PrtConnDet::Active
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == PrtConnDet::Inactive
    }
}
#[doc = "Field `PrtConnDet` writer - The core sets this bit when a device connection is detected to trigger an interrupt to the application using the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). This bit can be set only by the core and the application should write 1 to clear it.The application must write a 1 to this bit to clear the interrupt."]
pub type PrtConnDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "A port is enabled only by the core after a reset sequence, and is disabled by an overcurrent condition, a disconnect condition, or by the application clearing this bit. The application cannot Set this bit by a register write. It can only clear it to disable the port by writing 1. This bit does not trigger any interrupt to the application.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtena {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Prtena> for bool {
    #[inline(always)]
    fn from(variant: Prtena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtena` reader - A port is enabled only by the core after a reset sequence, and is disabled by an overcurrent condition, a disconnect condition, or by the application clearing this bit. The application cannot Set this bit by a register write. It can only clear it to disable the port by writing 1. This bit does not trigger any interrupt to the application."]
pub type PrtenaR = crate::BitReader<Prtena>;
impl PrtenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtena {
        match self.bits {
            false => Prtena::Disabled,
            true => Prtena::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Prtena::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Prtena::Enabled
    }
}
#[doc = "Field `prtena` writer - A port is enabled only by the core after a reset sequence, and is disabled by an overcurrent condition, a disconnect condition, or by the application clearing this bit. The application cannot Set this bit by a register write. It can only clear it to disable the port by writing 1. This bit does not trigger any interrupt to the application."]
pub type PrtenaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core sets this bit when the status of the Port Enable bit \\[2\\]
of this register changes. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtenchng {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prtenchng> for bool {
    #[inline(always)]
    fn from(variant: Prtenchng) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtenchng` reader - The core sets this bit when the status of the Port Enable bit \\[2\\]
of this register changes. This bit can be set only by the core and the application should write 1 to clear it."]
pub type PrtenchngR = crate::BitReader<Prtenchng>;
impl PrtenchngR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtenchng {
        match self.bits {
            false => Prtenchng::Inactive,
            true => Prtenchng::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prtenchng::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prtenchng::Active
    }
}
#[doc = "Field `prtenchng` writer - The core sets this bit when the status of the Port Enable bit \\[2\\]
of this register changes. This bit can be set only by the core and the application should write 1 to clear it."]
pub type PrtenchngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates the overcurrent condition of the port. 0x0: No overcurrent condition 0x1: Overcurrent condition\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtovrcurract {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prtovrcurract> for bool {
    #[inline(always)]
    fn from(variant: Prtovrcurract) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtovrcurract` reader - Indicates the overcurrent condition of the port. 0x0: No overcurrent condition 0x1: Overcurrent condition"]
pub type PrtovrcurractR = crate::BitReader<Prtovrcurract>;
impl PrtovrcurractR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtovrcurract {
        match self.bits {
            false => Prtovrcurract::Inactive,
            true => Prtovrcurract::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prtovrcurract::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prtovrcurract::Active
    }
}
#[doc = "Field `prtovrcurract` writer - Indicates the overcurrent condition of the port. 0x0: No overcurrent condition 0x1: Overcurrent condition"]
pub type PrtovrcurractW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core sets this bit when the status of the PortOvercurrent Active bit (bit 4) in this register changes.This bit can be set only by the core and the application should write 1 to clear it\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtovrcurrchng {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prtovrcurrchng> for bool {
    #[inline(always)]
    fn from(variant: Prtovrcurrchng) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtovrcurrchng` reader - The core sets this bit when the status of the PortOvercurrent Active bit (bit 4) in this register changes.This bit can be set only by the core and the application should write 1 to clear it"]
pub type PrtovrcurrchngR = crate::BitReader<Prtovrcurrchng>;
impl PrtovrcurrchngR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtovrcurrchng {
        match self.bits {
            false => Prtovrcurrchng::Inactive,
            true => Prtovrcurrchng::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prtovrcurrchng::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prtovrcurrchng::Active
    }
}
#[doc = "Field `prtovrcurrchng` writer - The core sets this bit when the status of the PortOvercurrent Active bit (bit 4) in this register changes.This bit can be set only by the core and the application should write 1 to clear it"]
pub type PrtovrcurrchngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The application sets this bit to drive resume signaling on the port. The core continues to drive the resume signal until the application clears this bit. If the core detects a USB remote wakeup sequence, as indicated by the Port Resume/Remote Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.WkUpInt), the core starts driving resume signaling without application intervention and clears this bit when it detects a disconnect condition. The read value of this bit indicates whether the core is currently drivingresume signaling. When LPM is enabled and the core is in the L1 (Sleep) state, setting this bit results in the following behavior: The core continues to drive the resume signal until a pre-determined time specified in the GLPMCFG.HIRD_Thres\\[3:0\\]
field. If the core detects a USB remote wakeup sequence, as indicated by the Port L1 Resume/Remote L1 Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.L1WkUpInt), the core starts driving resume signaling without application intervention and clears this bit at the end of the resume. The read value of this bit indicates whether the core is currently driving resume signaling.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtres {
    #[doc = "0: `0`"]
    Noresume = 0,
    #[doc = "1: `1`"]
    Resume = 1,
}
impl From<Prtres> for bool {
    #[inline(always)]
    fn from(variant: Prtres) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtres` reader - The application sets this bit to drive resume signaling on the port. The core continues to drive the resume signal until the application clears this bit. If the core detects a USB remote wakeup sequence, as indicated by the Port Resume/Remote Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.WkUpInt), the core starts driving resume signaling without application intervention and clears this bit when it detects a disconnect condition. The read value of this bit indicates whether the core is currently drivingresume signaling. When LPM is enabled and the core is in the L1 (Sleep) state, setting this bit results in the following behavior: The core continues to drive the resume signal until a pre-determined time specified in the GLPMCFG.HIRD_Thres\\[3:0\\]
field. If the core detects a USB remote wakeup sequence, as indicated by the Port L1 Resume/Remote L1 Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.L1WkUpInt), the core starts driving resume signaling without application intervention and clears this bit at the end of the resume. The read value of this bit indicates whether the core is currently driving resume signaling."]
pub type PrtresR = crate::BitReader<Prtres>;
impl PrtresR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtres {
        match self.bits {
            false => Prtres::Noresume,
            true => Prtres::Resume,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noresume(&self) -> bool {
        *self == Prtres::Noresume
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_resume(&self) -> bool {
        *self == Prtres::Resume
    }
}
#[doc = "Field `prtres` writer - The application sets this bit to drive resume signaling on the port. The core continues to drive the resume signal until the application clears this bit. If the core detects a USB remote wakeup sequence, as indicated by the Port Resume/Remote Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.WkUpInt), the core starts driving resume signaling without application intervention and clears this bit when it detects a disconnect condition. The read value of this bit indicates whether the core is currently drivingresume signaling. When LPM is enabled and the core is in the L1 (Sleep) state, setting this bit results in the following behavior: The core continues to drive the resume signal until a pre-determined time specified in the GLPMCFG.HIRD_Thres\\[3:0\\]
field. If the core detects a USB remote wakeup sequence, as indicated by the Port L1 Resume/Remote L1 Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.L1WkUpInt), the core starts driving resume signaling without application intervention and clears this bit at the end of the resume. The read value of this bit indicates whether the core is currently driving resume signaling."]
pub type PrtresW<'a, REG> = crate::BitWriter<'a, REG, Prtres>;
impl<'a, REG> PrtresW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noresume(self) -> &'a mut crate::W<REG> {
        self.variant(Prtres::Noresume)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn resume(self) -> &'a mut crate::W<REG> {
        self.variant(Prtres::Resume)
    }
}
#[doc = "The application sets this bit to put this port in Suspend mode. The core only stops sending SOFs when this is Set. To stop the PHY clock, the application must Set the Port Clock Stop bit, which asserts the suspend input pin of the PHY. The read value of this bit reflects the current suspend status of the port. This bit is cleared by the core after a remote wakeup signal is detected or the application sets the Port Reset bit or Port Resume bit in this register or the Resume/Remote Wakeup Detected Interrupt bit or Disconnect Detected Interrupt bit in the Core Interrupt register (GINTSTS.WkUpInt or GINTSTS.DisconnInt, respectively). This bit is cleared by the core even if there is no device connected to the Host.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtsusp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prtsusp> for bool {
    #[inline(always)]
    fn from(variant: Prtsusp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtsusp` reader - The application sets this bit to put this port in Suspend mode. The core only stops sending SOFs when this is Set. To stop the PHY clock, the application must Set the Port Clock Stop bit, which asserts the suspend input pin of the PHY. The read value of this bit reflects the current suspend status of the port. This bit is cleared by the core after a remote wakeup signal is detected or the application sets the Port Reset bit or Port Resume bit in this register or the Resume/Remote Wakeup Detected Interrupt bit or Disconnect Detected Interrupt bit in the Core Interrupt register (GINTSTS.WkUpInt or GINTSTS.DisconnInt, respectively). This bit is cleared by the core even if there is no device connected to the Host."]
pub type PrtsuspR = crate::BitReader<Prtsusp>;
impl PrtsuspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtsusp {
        match self.bits {
            false => Prtsusp::Inactive,
            true => Prtsusp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prtsusp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prtsusp::Active
    }
}
#[doc = "Field `prtsusp` writer - The application sets this bit to put this port in Suspend mode. The core only stops sending SOFs when this is Set. To stop the PHY clock, the application must Set the Port Clock Stop bit, which asserts the suspend input pin of the PHY. The read value of this bit reflects the current suspend status of the port. This bit is cleared by the core after a remote wakeup signal is detected or the application sets the Port Reset bit or Port Resume bit in this register or the Resume/Remote Wakeup Detected Interrupt bit or Disconnect Detected Interrupt bit in the Core Interrupt register (GINTSTS.WkUpInt or GINTSTS.DisconnInt, respectively). This bit is cleared by the core even if there is no device connected to the Host."]
pub type PrtsuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When the application sets this bit, a reset sequence is started on this port. The application must time the reset period and clear this bit after the reset sequence is complete. The application must leave this bit Set for at least a minimum duration mentioned below to start a reset on the port. The application can leave it Set for another 10 ms in addition to the required minimum duration, before clearing the bit, even though there is no maximum limit set by theUSB standard. This bit is cleared by the core even if there is no device connected to the Host. High speed: 50 ms Full speed/Low speed: 10 ms\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtrst {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Prtrst> for bool {
    #[inline(always)]
    fn from(variant: Prtrst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtrst` reader - When the application sets this bit, a reset sequence is started on this port. The application must time the reset period and clear this bit after the reset sequence is complete. The application must leave this bit Set for at least a minimum duration mentioned below to start a reset on the port. The application can leave it Set for another 10 ms in addition to the required minimum duration, before clearing the bit, even though there is no maximum limit set by theUSB standard. This bit is cleared by the core even if there is no device connected to the Host. High speed: 50 ms Full speed/Low speed: 10 ms"]
pub type PrtrstR = crate::BitReader<Prtrst>;
impl PrtrstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtrst {
        match self.bits {
            false => Prtrst::Disabled,
            true => Prtrst::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Prtrst::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Prtrst::Enabled
    }
}
#[doc = "Field `prtrst` writer - When the application sets this bit, a reset sequence is started on this port. The application must time the reset period and clear this bit after the reset sequence is complete. The application must leave this bit Set for at least a minimum duration mentioned below to start a reset on the port. The application can leave it Set for another 10 ms in addition to the required minimum duration, before clearing the bit, even though there is no maximum limit set by theUSB standard. This bit is cleared by the core even if there is no device connected to the Host. High speed: 50 ms Full speed/Low speed: 10 ms"]
pub type PrtrstW<'a, REG> = crate::BitWriter<'a, REG, Prtrst>;
impl<'a, REG> PrtrstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Prtrst::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Prtrst::Enabled)
    }
}
#[doc = "Indicates the current logic level USB data lines. Bit \\[10\\]: Logic level of D+ Bit \\[11\\]: Logic level of D-\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Prtlnsts {
    #[doc = "1: `1`"]
    Plusd = 1,
    #[doc = "2: `10`"]
    Minusd = 2,
}
impl From<Prtlnsts> for u8 {
    #[inline(always)]
    fn from(variant: Prtlnsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Prtlnsts {
    type Ux = u8;
}
#[doc = "Field `prtlnsts` reader - Indicates the current logic level USB data lines. Bit \\[10\\]: Logic level of D+ Bit \\[11\\]: Logic level of D-"]
pub type PrtlnstsR = crate::FieldReader<Prtlnsts>;
impl PrtlnstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Prtlnsts> {
        match self.bits {
            1 => Some(Prtlnsts::Plusd),
            2 => Some(Prtlnsts::Minusd),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_plusd(&self) -> bool {
        *self == Prtlnsts::Plusd
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_minusd(&self) -> bool {
        *self == Prtlnsts::Minusd
    }
}
#[doc = "Field `prtlnsts` writer - Indicates the current logic level USB data lines. Bit \\[10\\]: Logic level of D+ Bit \\[11\\]: Logic level of D-"]
pub type PrtlnstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "The application uses this field to control power to this port, and the core can clear this bit on an over current condition.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtpwr {
    #[doc = "0: `0`"]
    Off = 0,
    #[doc = "1: `1`"]
    On = 1,
}
impl From<Prtpwr> for bool {
    #[inline(always)]
    fn from(variant: Prtpwr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtpwr` reader - The application uses this field to control power to this port, and the core can clear this bit on an over current condition."]
pub type PrtpwrR = crate::BitReader<Prtpwr>;
impl PrtpwrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtpwr {
        match self.bits {
            false => Prtpwr::Off,
            true => Prtpwr::On,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_off(&self) -> bool {
        *self == Prtpwr::Off
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_on(&self) -> bool {
        *self == Prtpwr::On
    }
}
#[doc = "Field `prtpwr` writer - The application uses this field to control power to this port, and the core can clear this bit on an over current condition."]
pub type PrtpwrW<'a, REG> = crate::BitWriter<'a, REG, Prtpwr>;
impl<'a, REG> PrtpwrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn off(self) -> &'a mut crate::W<REG> {
        self.variant(Prtpwr::Off)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn on(self) -> &'a mut crate::W<REG> {
        self.variant(Prtpwr::On)
    }
}
#[doc = "The application writes a nonzero value to this field to put the port into a Test mode, and the corresponding pattern is signaled on the port.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Prttstctl {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Testj = 1,
    #[doc = "2: `10`"]
    Testk = 2,
    #[doc = "3: `11`"]
    Testsn = 3,
    #[doc = "4: `100`"]
    Testpm = 4,
    #[doc = "5: `101`"]
    Testfenb = 5,
}
impl From<Prttstctl> for u8 {
    #[inline(always)]
    fn from(variant: Prttstctl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Prttstctl {
    type Ux = u8;
}
#[doc = "Field `prttstctl` reader - The application writes a nonzero value to this field to put the port into a Test mode, and the corresponding pattern is signaled on the port."]
pub type PrttstctlR = crate::FieldReader<Prttstctl>;
impl PrttstctlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Prttstctl> {
        match self.bits {
            0 => Some(Prttstctl::Disabled),
            1 => Some(Prttstctl::Testj),
            2 => Some(Prttstctl::Testk),
            3 => Some(Prttstctl::Testsn),
            4 => Some(Prttstctl::Testpm),
            5 => Some(Prttstctl::Testfenb),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Prttstctl::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_testj(&self) -> bool {
        *self == Prttstctl::Testj
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_testk(&self) -> bool {
        *self == Prttstctl::Testk
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_testsn(&self) -> bool {
        *self == Prttstctl::Testsn
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_testpm(&self) -> bool {
        *self == Prttstctl::Testpm
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_testfenb(&self) -> bool {
        *self == Prttstctl::Testfenb
    }
}
#[doc = "Field `prttstctl` writer - The application writes a nonzero value to this field to put the port into a Test mode, and the corresponding pattern is signaled on the port."]
pub type PrttstctlW<'a, REG> = crate::FieldWriter<'a, REG, 4, Prttstctl>;
impl<'a, REG> PrttstctlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Prttstctl::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn testj(self) -> &'a mut crate::W<REG> {
        self.variant(Prttstctl::Testj)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn testk(self) -> &'a mut crate::W<REG> {
        self.variant(Prttstctl::Testk)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn testsn(self) -> &'a mut crate::W<REG> {
        self.variant(Prttstctl::Testsn)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn testpm(self) -> &'a mut crate::W<REG> {
        self.variant(Prttstctl::Testpm)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn testfenb(self) -> &'a mut crate::W<REG> {
        self.variant(Prttstctl::Testfenb)
    }
}
#[doc = "Indicates the speed of the device attached to this port.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Prtspd {
    #[doc = "0: `0`"]
    Highspd = 0,
    #[doc = "1: `1`"]
    Fullspd = 1,
    #[doc = "2: `10`"]
    Lowspd = 2,
}
impl From<Prtspd> for u8 {
    #[inline(always)]
    fn from(variant: Prtspd) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Prtspd {
    type Ux = u8;
}
#[doc = "Field `prtspd` reader - Indicates the speed of the device attached to this port."]
pub type PrtspdR = crate::FieldReader<Prtspd>;
impl PrtspdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtspd {
        match self.bits {
            0 => Prtspd::Highspd,
            1 => Prtspd::Fullspd,
            2 => Prtspd::Lowspd,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_highspd(&self) -> bool {
        *self == Prtspd::Highspd
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fullspd(&self) -> bool {
        *self == Prtspd::Fullspd
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_lowspd(&self) -> bool {
        *self == Prtspd::Lowspd
    }
}
#[doc = "Field `prtspd` writer - Indicates the speed of the device attached to this port."]
pub type PrtspdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Defines whether port is attached."]
    #[inline(always)]
    pub fn prtconnsts(&self) -> PrtconnstsR {
        PrtconnstsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - The core sets this bit when a device connection is detected to trigger an interrupt to the application using the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). This bit can be set only by the core and the application should write 1 to clear it.The application must write a 1 to this bit to clear the interrupt."]
    #[inline(always)]
    pub fn prt_conn_det(&self) -> PrtConnDetR {
        PrtConnDetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - A port is enabled only by the core after a reset sequence, and is disabled by an overcurrent condition, a disconnect condition, or by the application clearing this bit. The application cannot Set this bit by a register write. It can only clear it to disable the port by writing 1. This bit does not trigger any interrupt to the application."]
    #[inline(always)]
    pub fn prtena(&self) -> PrtenaR {
        PrtenaR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - The core sets this bit when the status of the Port Enable bit \\[2\\]
of this register changes. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn prtenchng(&self) -> PrtenchngR {
        PrtenchngR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Indicates the overcurrent condition of the port. 0x0: No overcurrent condition 0x1: Overcurrent condition"]
    #[inline(always)]
    pub fn prtovrcurract(&self) -> PrtovrcurractR {
        PrtovrcurractR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - The core sets this bit when the status of the PortOvercurrent Active bit (bit 4) in this register changes.This bit can be set only by the core and the application should write 1 to clear it"]
    #[inline(always)]
    pub fn prtovrcurrchng(&self) -> PrtovrcurrchngR {
        PrtovrcurrchngR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - The application sets this bit to drive resume signaling on the port. The core continues to drive the resume signal until the application clears this bit. If the core detects a USB remote wakeup sequence, as indicated by the Port Resume/Remote Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.WkUpInt), the core starts driving resume signaling without application intervention and clears this bit when it detects a disconnect condition. The read value of this bit indicates whether the core is currently drivingresume signaling. When LPM is enabled and the core is in the L1 (Sleep) state, setting this bit results in the following behavior: The core continues to drive the resume signal until a pre-determined time specified in the GLPMCFG.HIRD_Thres\\[3:0\\]
field. If the core detects a USB remote wakeup sequence, as indicated by the Port L1 Resume/Remote L1 Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.L1WkUpInt), the core starts driving resume signaling without application intervention and clears this bit at the end of the resume. The read value of this bit indicates whether the core is currently driving resume signaling."]
    #[inline(always)]
    pub fn prtres(&self) -> PrtresR {
        PrtresR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - The application sets this bit to put this port in Suspend mode. The core only stops sending SOFs when this is Set. To stop the PHY clock, the application must Set the Port Clock Stop bit, which asserts the suspend input pin of the PHY. The read value of this bit reflects the current suspend status of the port. This bit is cleared by the core after a remote wakeup signal is detected or the application sets the Port Reset bit or Port Resume bit in this register or the Resume/Remote Wakeup Detected Interrupt bit or Disconnect Detected Interrupt bit in the Core Interrupt register (GINTSTS.WkUpInt or GINTSTS.DisconnInt, respectively). This bit is cleared by the core even if there is no device connected to the Host."]
    #[inline(always)]
    pub fn prtsusp(&self) -> PrtsuspR {
        PrtsuspR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - When the application sets this bit, a reset sequence is started on this port. The application must time the reset period and clear this bit after the reset sequence is complete. The application must leave this bit Set for at least a minimum duration mentioned below to start a reset on the port. The application can leave it Set for another 10 ms in addition to the required minimum duration, before clearing the bit, even though there is no maximum limit set by theUSB standard. This bit is cleared by the core even if there is no device connected to the Host. High speed: 50 ms Full speed/Low speed: 10 ms"]
    #[inline(always)]
    pub fn prtrst(&self) -> PrtrstR {
        PrtrstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bits 10:11 - Indicates the current logic level USB data lines. Bit \\[10\\]: Logic level of D+ Bit \\[11\\]: Logic level of D-"]
    #[inline(always)]
    pub fn prtlnsts(&self) -> PrtlnstsR {
        PrtlnstsR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bit 12 - The application uses this field to control power to this port, and the core can clear this bit on an over current condition."]
    #[inline(always)]
    pub fn prtpwr(&self) -> PrtpwrR {
        PrtpwrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bits 13:16 - The application writes a nonzero value to this field to put the port into a Test mode, and the corresponding pattern is signaled on the port."]
    #[inline(always)]
    pub fn prttstctl(&self) -> PrttstctlR {
        PrttstctlR::new(((self.bits >> 13) & 0x0f) as u8)
    }
    #[doc = "Bits 17:18 - Indicates the speed of the device attached to this port."]
    #[inline(always)]
    pub fn prtspd(&self) -> PrtspdR {
        PrtspdR::new(((self.bits >> 17) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Defines whether port is attached."]
    #[inline(always)]
    #[must_use]
    pub fn prtconnsts(&mut self) -> PrtconnstsW<HostgrpHprtSpec> {
        PrtconnstsW::new(self, 0)
    }
    #[doc = "Bit 1 - The core sets this bit when a device connection is detected to trigger an interrupt to the application using the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). This bit can be set only by the core and the application should write 1 to clear it.The application must write a 1 to this bit to clear the interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn prt_conn_det(&mut self) -> PrtConnDetW<HostgrpHprtSpec> {
        PrtConnDetW::new(self, 1)
    }
    #[doc = "Bit 2 - A port is enabled only by the core after a reset sequence, and is disabled by an overcurrent condition, a disconnect condition, or by the application clearing this bit. The application cannot Set this bit by a register write. It can only clear it to disable the port by writing 1. This bit does not trigger any interrupt to the application."]
    #[inline(always)]
    #[must_use]
    pub fn prtena(&mut self) -> PrtenaW<HostgrpHprtSpec> {
        PrtenaW::new(self, 2)
    }
    #[doc = "Bit 3 - The core sets this bit when the status of the Port Enable bit \\[2\\]
of this register changes. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn prtenchng(&mut self) -> PrtenchngW<HostgrpHprtSpec> {
        PrtenchngW::new(self, 3)
    }
    #[doc = "Bit 4 - Indicates the overcurrent condition of the port. 0x0: No overcurrent condition 0x1: Overcurrent condition"]
    #[inline(always)]
    #[must_use]
    pub fn prtovrcurract(&mut self) -> PrtovrcurractW<HostgrpHprtSpec> {
        PrtovrcurractW::new(self, 4)
    }
    #[doc = "Bit 5 - The core sets this bit when the status of the PortOvercurrent Active bit (bit 4) in this register changes.This bit can be set only by the core and the application should write 1 to clear it"]
    #[inline(always)]
    #[must_use]
    pub fn prtovrcurrchng(&mut self) -> PrtovrcurrchngW<HostgrpHprtSpec> {
        PrtovrcurrchngW::new(self, 5)
    }
    #[doc = "Bit 6 - The application sets this bit to drive resume signaling on the port. The core continues to drive the resume signal until the application clears this bit. If the core detects a USB remote wakeup sequence, as indicated by the Port Resume/Remote Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.WkUpInt), the core starts driving resume signaling without application intervention and clears this bit when it detects a disconnect condition. The read value of this bit indicates whether the core is currently drivingresume signaling. When LPM is enabled and the core is in the L1 (Sleep) state, setting this bit results in the following behavior: The core continues to drive the resume signal until a pre-determined time specified in the GLPMCFG.HIRD_Thres\\[3:0\\]
field. If the core detects a USB remote wakeup sequence, as indicated by the Port L1 Resume/Remote L1 Wakeup Detected Interrupt bit of the Core Interrupt register (GINTSTS.L1WkUpInt), the core starts driving resume signaling without application intervention and clears this bit at the end of the resume. The read value of this bit indicates whether the core is currently driving resume signaling."]
    #[inline(always)]
    #[must_use]
    pub fn prtres(&mut self) -> PrtresW<HostgrpHprtSpec> {
        PrtresW::new(self, 6)
    }
    #[doc = "Bit 7 - The application sets this bit to put this port in Suspend mode. The core only stops sending SOFs when this is Set. To stop the PHY clock, the application must Set the Port Clock Stop bit, which asserts the suspend input pin of the PHY. The read value of this bit reflects the current suspend status of the port. This bit is cleared by the core after a remote wakeup signal is detected or the application sets the Port Reset bit or Port Resume bit in this register or the Resume/Remote Wakeup Detected Interrupt bit or Disconnect Detected Interrupt bit in the Core Interrupt register (GINTSTS.WkUpInt or GINTSTS.DisconnInt, respectively). This bit is cleared by the core even if there is no device connected to the Host."]
    #[inline(always)]
    #[must_use]
    pub fn prtsusp(&mut self) -> PrtsuspW<HostgrpHprtSpec> {
        PrtsuspW::new(self, 7)
    }
    #[doc = "Bit 8 - When the application sets this bit, a reset sequence is started on this port. The application must time the reset period and clear this bit after the reset sequence is complete. The application must leave this bit Set for at least a minimum duration mentioned below to start a reset on the port. The application can leave it Set for another 10 ms in addition to the required minimum duration, before clearing the bit, even though there is no maximum limit set by theUSB standard. This bit is cleared by the core even if there is no device connected to the Host. High speed: 50 ms Full speed/Low speed: 10 ms"]
    #[inline(always)]
    #[must_use]
    pub fn prtrst(&mut self) -> PrtrstW<HostgrpHprtSpec> {
        PrtrstW::new(self, 8)
    }
    #[doc = "Bits 10:11 - Indicates the current logic level USB data lines. Bit \\[10\\]: Logic level of D+ Bit \\[11\\]: Logic level of D-"]
    #[inline(always)]
    #[must_use]
    pub fn prtlnsts(&mut self) -> PrtlnstsW<HostgrpHprtSpec> {
        PrtlnstsW::new(self, 10)
    }
    #[doc = "Bit 12 - The application uses this field to control power to this port, and the core can clear this bit on an over current condition."]
    #[inline(always)]
    #[must_use]
    pub fn prtpwr(&mut self) -> PrtpwrW<HostgrpHprtSpec> {
        PrtpwrW::new(self, 12)
    }
    #[doc = "Bits 13:16 - The application writes a nonzero value to this field to put the port into a Test mode, and the corresponding pattern is signaled on the port."]
    #[inline(always)]
    #[must_use]
    pub fn prttstctl(&mut self) -> PrttstctlW<HostgrpHprtSpec> {
        PrttstctlW::new(self, 13)
    }
    #[doc = "Bits 17:18 - Indicates the speed of the device attached to this port."]
    #[inline(always)]
    #[must_use]
    pub fn prtspd(&mut self) -> PrtspdW<HostgrpHprtSpec> {
        PrtspdW::new(self, 17)
    }
}
#[doc = "This register is available only in Host mode. Currently, the OTG Host supports only one port. A single register holds USB port-related information such as USB reset, enable, suspend, resume, connect status, and test mode for each port.The R_SS_WC bits in this register can trigger an interrupt to the application through the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). On a Port Interrupt, the application must read this register and clear the bit that caused the interrupt. for the R_SS_WC bits, the application must write a 1 to the bit to clear the interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hprt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hprt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHprtSpec;
impl crate::RegisterSpec for HostgrpHprtSpec {
    type Ux = u32;
    const OFFSET: u64 = 1088u64;
}
#[doc = "`read()` method returns [`hostgrp_hprt::R`](R) reader structure"]
impl crate::Readable for HostgrpHprtSpec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hprt::W`](W) writer structure"]
impl crate::Writable for HostgrpHprtSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hprt to value 0"]
impl crate::Resettable for HostgrpHprtSpec {
    const RESET_VALUE: u32 = 0;
}
