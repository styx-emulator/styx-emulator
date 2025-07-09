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
#[doc = "Register `devgrp_doepctl0` reader"]
pub type R = crate::R<DevgrpDoepctl0Spec>;
#[doc = "Register `devgrp_doepctl0` writer"]
pub type W = crate::W<DevgrpDoepctl0Spec>;
#[doc = "The maximum packet size for control OUT endpoint 0 is thesame as what is programmed in control IN Endpoint 0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mps {
    #[doc = "0: `0`"]
    Byte64 = 0,
    #[doc = "1: `1`"]
    Byte32 = 1,
    #[doc = "2: `10`"]
    Byte16 = 2,
    #[doc = "3: `11`"]
    Byte8 = 3,
}
impl From<Mps> for u8 {
    #[inline(always)]
    fn from(variant: Mps) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Mps {
    type Ux = u8;
}
#[doc = "Field `mps` reader - The maximum packet size for control OUT endpoint 0 is thesame as what is programmed in control IN Endpoint 0."]
pub type MpsR = crate::FieldReader<Mps>;
impl MpsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mps {
        match self.bits {
            0 => Mps::Byte64,
            1 => Mps::Byte32,
            2 => Mps::Byte16,
            3 => Mps::Byte8,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_byte64(&self) -> bool {
        *self == Mps::Byte64
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_byte32(&self) -> bool {
        *self == Mps::Byte32
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_byte16(&self) -> bool {
        *self == Mps::Byte16
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_byte8(&self) -> bool {
        *self == Mps::Byte8
    }
}
#[doc = "Field `mps` writer - The maximum packet size for control OUT endpoint 0 is thesame as what is programmed in control IN Endpoint 0."]
pub type MpsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "This bit is always Set to 1, indicating that a control endpoint 0 is always active in all configurations and interfaces.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbactep {
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Usbactep> for bool {
    #[inline(always)]
    fn from(variant: Usbactep) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbactep` reader - This bit is always Set to 1, indicating that a control endpoint 0 is always active in all configurations and interfaces."]
pub type UsbactepR = crate::BitReader<Usbactep>;
impl UsbactepR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Usbactep> {
        match self.bits {
            true => Some(Usbactep::Active),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Usbactep::Active
    }
}
#[doc = "Field `usbactep` writer - This bit is always Set to 1, indicating that a control endpoint 0 is always active in all configurations and interfaces."]
pub type UsbactepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When either the application or the core sets this bit, the core stops receiving data, even If there is space in the RxFIFO to accommodate the incoming packet. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Naksts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Naksts> for bool {
    #[inline(always)]
    fn from(variant: Naksts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `naksts` reader - When either the application or the core sets this bit, the core stops receiving data, even If there is space in the RxFIFO to accommodate the incoming packet. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type NakstsR = crate::BitReader<Naksts>;
impl NakstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Naksts {
        match self.bits {
            false => Naksts::Inactive,
            true => Naksts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Naksts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Naksts::Active
    }
}
#[doc = "Field `naksts` writer - When either the application or the core sets this bit, the core stops receiving data, even If there is space in the RxFIFO to accommodate the incoming packet. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type NakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Hardcoded to 0 for control.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Eptype {
    #[doc = "0: `0`"]
    Active = 0,
}
impl From<Eptype> for u8 {
    #[inline(always)]
    fn from(variant: Eptype) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Eptype {
    type Ux = u8;
}
#[doc = "Field `eptype` reader - Hardcoded to 0 for control."]
pub type EptypeR = crate::FieldReader<Eptype>;
impl EptypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Eptype> {
        match self.bits {
            0 => Some(Eptype::Active),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Eptype::Active
    }
}
#[doc = "Field `eptype` writer - Hardcoded to 0 for control."]
pub type EptypeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "This bit configures the endpoint to Snoop mode. In Snoop mode, the core does not check the correctness of OUT packets before transferring them to application memory.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Snp {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Snp> for bool {
    #[inline(always)]
    fn from(variant: Snp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `snp` reader - This bit configures the endpoint to Snoop mode. In Snoop mode, the core does not check the correctness of OUT packets before transferring them to application memory."]
pub type SnpR = crate::BitReader<Snp>;
impl SnpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Snp {
        match self.bits {
            false => Snp::Disabled,
            true => Snp::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Snp::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Snp::Enabled
    }
}
#[doc = "Field `snp` writer - This bit configures the endpoint to Snoop mode. In Snoop mode, the core does not check the correctness of OUT packets before transferring them to application memory."]
pub type SnpW<'a, REG> = crate::BitWriter<'a, REG, Snp>;
impl<'a, REG> SnpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Snp::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Snp::Enabled)
    }
}
#[doc = "The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit or Global OUT NAK is Set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stall {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Stall> for bool {
    #[inline(always)]
    fn from(variant: Stall) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stall` reader - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit or Global OUT NAK is Set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type StallR = crate::BitReader<Stall>;
impl StallR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stall {
        match self.bits {
            false => Stall::Inactive,
            true => Stall::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Stall::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Stall::Active
    }
}
#[doc = "Field `stall` writer - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit or Global OUT NAK is Set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type StallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cnak` reader - A write to this bit clears the NAK bit for the endpoint."]
pub type CnakR = crate::BitReader;
#[doc = "A write to this bit clears the NAK bit for the endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cnak {
    #[doc = "0: `0`"]
    Noclear = 0,
    #[doc = "1: `1`"]
    Clear = 1,
}
impl From<Cnak> for bool {
    #[inline(always)]
    fn from(variant: Cnak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cnak` writer - A write to this bit clears the NAK bit for the endpoint."]
pub type CnakW<'a, REG> = crate::BitWriter<'a, REG, Cnak>;
impl<'a, REG> CnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noclear(self) -> &'a mut crate::W<REG> {
        self.variant(Cnak::Noclear)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clear(self) -> &'a mut crate::W<REG> {
        self.variant(Cnak::Clear)
    }
}
#[doc = "Field `snak` reader - A write to this bit sets the NAK bit for the endpoint.Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set bit on a Transfer Completed interrupt, or after a SETUP is received on the endpoint."]
pub type SnakR = crate::BitReader;
#[doc = "A write to this bit sets the NAK bit for the endpoint.Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set bit on a Transfer Completed interrupt, or after a SETUP is received on the endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Snak {
    #[doc = "0: `0`"]
    Noset = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<Snak> for bool {
    #[inline(always)]
    fn from(variant: Snak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `snak` writer - A write to this bit sets the NAK bit for the endpoint.Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set bit on a Transfer Completed interrupt, or after a SETUP is received on the endpoint."]
pub type SnakW<'a, REG> = crate::BitWriter<'a, REG, Snak>;
impl<'a, REG> SnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noset(self) -> &'a mut crate::W<REG> {
        self.variant(Snak::Noset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn set(self) -> &'a mut crate::W<REG> {
        self.variant(Snak::Set)
    }
}
#[doc = "The application cannot disable control OUT endpoint 0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epdis {
    #[doc = "0: `0`"]
    Inactive = 0,
}
impl From<Epdis> for bool {
    #[inline(always)]
    fn from(variant: Epdis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epdis` reader - The application cannot disable control OUT endpoint 0."]
pub type EpdisR = crate::BitReader<Epdis>;
impl EpdisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Epdis> {
        match self.bits {
            false => Some(Epdis::Inactive),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Epdis::Inactive
    }
}
#[doc = "Field `epdis` writer - The application cannot disable control OUT endpoint 0."]
pub type EpdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When Scatter/Gather DMA mode is enabled, for OUT endpoints this bit indicates that the descriptor structure and data buffer to receive data is setup. When Scatter/Gather DMA mode is disabled(such as for buffer-pointer based DMA mode)this bit indicates that the application has allocated the memory to start receiving data from the USB.The core clears this bit before setting any of the following interrupts on this endpoint: SETUP Phase Done Endpoint Disabled Transfer Completed In DMA mode, this bit must be Set for the core to transfer SETUP data packets into memory.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epena {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Epena> for bool {
    #[inline(always)]
    fn from(variant: Epena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epena` reader - When Scatter/Gather DMA mode is enabled, for OUT endpoints this bit indicates that the descriptor structure and data buffer to receive data is setup. When Scatter/Gather DMA mode is disabled(such as for buffer-pointer based DMA mode)this bit indicates that the application has allocated the memory to start receiving data from the USB.The core clears this bit before setting any of the following interrupts on this endpoint: SETUP Phase Done Endpoint Disabled Transfer Completed In DMA mode, this bit must be Set for the core to transfer SETUP data packets into memory."]
pub type EpenaR = crate::BitReader<Epena>;
impl EpenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epena {
        match self.bits {
            false => Epena::Inactive,
            true => Epena::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Epena::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Epena::Active
    }
}
#[doc = "Field `epena` writer - When Scatter/Gather DMA mode is enabled, for OUT endpoints this bit indicates that the descriptor structure and data buffer to receive data is setup. When Scatter/Gather DMA mode is disabled(such as for buffer-pointer based DMA mode)this bit indicates that the application has allocated the memory to start receiving data from the USB.The core clears this bit before setting any of the following interrupts on this endpoint: SETUP Phase Done Endpoint Disabled Transfer Completed In DMA mode, this bit must be Set for the core to transfer SETUP data packets into memory."]
pub type EpenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - The maximum packet size for control OUT endpoint 0 is thesame as what is programmed in control IN Endpoint 0."]
    #[inline(always)]
    pub fn mps(&self) -> MpsR {
        MpsR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 15 - This bit is always Set to 1, indicating that a control endpoint 0 is always active in all configurations and interfaces."]
    #[inline(always)]
    pub fn usbactep(&self) -> UsbactepR {
        UsbactepR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - When either the application or the core sets this bit, the core stops receiving data, even If there is space in the RxFIFO to accommodate the incoming packet. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    pub fn naksts(&self) -> NakstsR {
        NakstsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - Hardcoded to 0 for control."]
    #[inline(always)]
    pub fn eptype(&self) -> EptypeR {
        EptypeR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bit 20 - This bit configures the endpoint to Snoop mode. In Snoop mode, the core does not check the correctness of OUT packets before transferring them to application memory."]
    #[inline(always)]
    pub fn snp(&self) -> SnpR {
        SnpR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit or Global OUT NAK is Set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    pub fn stall(&self) -> StallR {
        StallR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 26 - A write to this bit clears the NAK bit for the endpoint."]
    #[inline(always)]
    pub fn cnak(&self) -> CnakR {
        CnakR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - A write to this bit sets the NAK bit for the endpoint.Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set bit on a Transfer Completed interrupt, or after a SETUP is received on the endpoint."]
    #[inline(always)]
    pub fn snak(&self) -> SnakR {
        SnakR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 30 - The application cannot disable control OUT endpoint 0."]
    #[inline(always)]
    pub fn epdis(&self) -> EpdisR {
        EpdisR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - When Scatter/Gather DMA mode is enabled, for OUT endpoints this bit indicates that the descriptor structure and data buffer to receive data is setup. When Scatter/Gather DMA mode is disabled(such as for buffer-pointer based DMA mode)this bit indicates that the application has allocated the memory to start receiving data from the USB.The core clears this bit before setting any of the following interrupts on this endpoint: SETUP Phase Done Endpoint Disabled Transfer Completed In DMA mode, this bit must be Set for the core to transfer SETUP data packets into memory."]
    #[inline(always)]
    pub fn epena(&self) -> EpenaR {
        EpenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - The maximum packet size for control OUT endpoint 0 is thesame as what is programmed in control IN Endpoint 0."]
    #[inline(always)]
    #[must_use]
    pub fn mps(&mut self) -> MpsW<DevgrpDoepctl0Spec> {
        MpsW::new(self, 0)
    }
    #[doc = "Bit 15 - This bit is always Set to 1, indicating that a control endpoint 0 is always active in all configurations and interfaces."]
    #[inline(always)]
    #[must_use]
    pub fn usbactep(&mut self) -> UsbactepW<DevgrpDoepctl0Spec> {
        UsbactepW::new(self, 15)
    }
    #[doc = "Bit 17 - When either the application or the core sets this bit, the core stops receiving data, even If there is space in the RxFIFO to accommodate the incoming packet. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    #[must_use]
    pub fn naksts(&mut self) -> NakstsW<DevgrpDoepctl0Spec> {
        NakstsW::new(self, 17)
    }
    #[doc = "Bits 18:19 - Hardcoded to 0 for control."]
    #[inline(always)]
    #[must_use]
    pub fn eptype(&mut self) -> EptypeW<DevgrpDoepctl0Spec> {
        EptypeW::new(self, 18)
    }
    #[doc = "Bit 20 - This bit configures the endpoint to Snoop mode. In Snoop mode, the core does not check the correctness of OUT packets before transferring them to application memory."]
    #[inline(always)]
    #[must_use]
    pub fn snp(&mut self) -> SnpW<DevgrpDoepctl0Spec> {
        SnpW::new(self, 20)
    }
    #[doc = "Bit 21 - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit or Global OUT NAK is Set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    #[must_use]
    pub fn stall(&mut self) -> StallW<DevgrpDoepctl0Spec> {
        StallW::new(self, 21)
    }
    #[doc = "Bit 26 - A write to this bit clears the NAK bit for the endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn cnak(&mut self) -> CnakW<DevgrpDoepctl0Spec> {
        CnakW::new(self, 26)
    }
    #[doc = "Bit 27 - A write to this bit sets the NAK bit for the endpoint.Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set bit on a Transfer Completed interrupt, or after a SETUP is received on the endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn snak(&mut self) -> SnakW<DevgrpDoepctl0Spec> {
        SnakW::new(self, 27)
    }
    #[doc = "Bit 30 - The application cannot disable control OUT endpoint 0."]
    #[inline(always)]
    #[must_use]
    pub fn epdis(&mut self) -> EpdisW<DevgrpDoepctl0Spec> {
        EpdisW::new(self, 30)
    }
    #[doc = "Bit 31 - When Scatter/Gather DMA mode is enabled, for OUT endpoints this bit indicates that the descriptor structure and data buffer to receive data is setup. When Scatter/Gather DMA mode is disabled(such as for buffer-pointer based DMA mode)this bit indicates that the application has allocated the memory to start receiving data from the USB.The core clears this bit before setting any of the following interrupts on this endpoint: SETUP Phase Done Endpoint Disabled Transfer Completed In DMA mode, this bit must be Set for the core to transfer SETUP data packets into memory."]
    #[inline(always)]
    #[must_use]
    pub fn epena(&mut self) -> EpenaW<DevgrpDoepctl0Spec> {
        EpenaW::new(self, 31)
    }
}
#[doc = "This is Control OUT Endpoint 0 Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepctl0Spec;
impl crate::RegisterSpec for DevgrpDoepctl0Spec {
    type Ux = u32;
    const OFFSET: u64 = 2816u64;
}
#[doc = "`read()` method returns [`devgrp_doepctl0::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepctl0Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_doepctl0::W`](W) writer structure"]
impl crate::Writable for DevgrpDoepctl0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_doepctl0 to value 0x8000"]
impl crate::Resettable for DevgrpDoepctl0Spec {
    const RESET_VALUE: u32 = 0x8000;
}
