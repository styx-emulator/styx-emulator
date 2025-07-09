// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepctl6` reader"]
pub type R = crate::R<DevgrpDiepctl6Spec>;
#[doc = "Register `devgrp_diepctl6` writer"]
pub type W = crate::W<DevgrpDiepctl6Spec>;
#[doc = "Field `mps` reader - Applies to IN and OUT endpoints. The application must program this field with the maximum packet size for the current logical endpoint. This value is in bytes."]
pub type MpsR = crate::FieldReader<u16>;
#[doc = "Field `mps` writer - Applies to IN and OUT endpoints. The application must program this field with the maximum packet size for the current logical endpoint. This value is in bytes."]
pub type MpsW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Indicates whether this endpoint is active in the current configuration and interface. The core clears this bit for all endpoints (other than EP 0) after detecting a USB reset. After receiving the SetConfiguration and SetInterface commands, the application must program endpoint registers accordingly and set this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbactep {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Usbactep> for bool {
    #[inline(always)]
    fn from(variant: Usbactep) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbactep` reader - Indicates whether this endpoint is active in the current configuration and interface. The core clears this bit for all endpoints (other than EP 0) after detecting a USB reset. After receiving the SetConfiguration and SetInterface commands, the application must program endpoint registers accordingly and set this bit."]
pub type UsbactepR = crate::BitReader<Usbactep>;
impl UsbactepR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usbactep {
        match self.bits {
            false => Usbactep::Disabled,
            true => Usbactep::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Usbactep::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Usbactep::Enabled
    }
}
#[doc = "Field `usbactep` writer - Indicates whether this endpoint is active in the current configuration and interface. The core clears this bit for all endpoints (other than EP 0) after detecting a USB reset. After receiving the SetConfiguration and SetInterface commands, the application must program endpoint registers accordingly and set this bit."]
pub type UsbactepW<'a, REG> = crate::BitWriter<'a, REG, Usbactep>;
impl<'a, REG> UsbactepW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Usbactep::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Usbactep::Enabled)
    }
}
#[doc = "Applies to interrupt/bulk IN and OUT endpoints only. Contains the PID of the packet to be received or transmitted on this endpoint. The application must program the PID of the first packet to be received or transmitted on this endpoint, after the endpoint is activated. The applications use the SetD1PID and SetD0PID fields of this register to program either DATA0 or DATA1 PID. 0: DATA0 1: DATA1This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Even/Odd (Micro)Frame (EO_FrNum) In non-Scatter/Gather DMA mode: Applies to isochronous IN and OUT endpoints only. Indicates the (micro)frame number in which the core transmits/receives isochronous data for this endpoint. The application must program the even/odd (micro) frame number in which it intends to transmit/receive isochronous data for this endpoint using the SetEvnFr and SetOddFr fields in this register. 0: Even (micro)frame 1: Odd (micro)frame When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is provided in the transmit descriptor structure. The frame in which data is received is updated in receive descriptor structure.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dpid {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Dpid> for bool {
    #[inline(always)]
    fn from(variant: Dpid) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dpid` reader - Applies to interrupt/bulk IN and OUT endpoints only. Contains the PID of the packet to be received or transmitted on this endpoint. The application must program the PID of the first packet to be received or transmitted on this endpoint, after the endpoint is activated. The applications use the SetD1PID and SetD0PID fields of this register to program either DATA0 or DATA1 PID. 0: DATA0 1: DATA1This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Even/Odd (Micro)Frame (EO_FrNum) In non-Scatter/Gather DMA mode: Applies to isochronous IN and OUT endpoints only. Indicates the (micro)frame number in which the core transmits/receives isochronous data for this endpoint. The application must program the even/odd (micro) frame number in which it intends to transmit/receive isochronous data for this endpoint using the SetEvnFr and SetOddFr fields in this register. 0: Even (micro)frame 1: Odd (micro)frame When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is provided in the transmit descriptor structure. The frame in which data is received is updated in receive descriptor structure."]
pub type DpidR = crate::BitReader<Dpid>;
impl DpidR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dpid {
        match self.bits {
            false => Dpid::Inactive,
            true => Dpid::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Dpid::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Dpid::Active
    }
}
#[doc = "Field `dpid` writer - Applies to interrupt/bulk IN and OUT endpoints only. Contains the PID of the packet to be received or transmitted on this endpoint. The application must program the PID of the first packet to be received or transmitted on this endpoint, after the endpoint is activated. The applications use the SetD1PID and SetD0PID fields of this register to program either DATA0 or DATA1 PID. 0: DATA0 1: DATA1This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Even/Odd (Micro)Frame (EO_FrNum) In non-Scatter/Gather DMA mode: Applies to isochronous IN and OUT endpoints only. Indicates the (micro)frame number in which the core transmits/receives isochronous data for this endpoint. The application must program the even/odd (micro) frame number in which it intends to transmit/receive isochronous data for this endpoint using the SetEvnFr and SetOddFr fields in this register. 0: Even (micro)frame 1: Odd (micro)frame When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is provided in the transmit descriptor structure. The frame in which data is received is updated in receive descriptor structure."]
pub type DpidW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When either the application or the core sets this bit: -The core stops receiving any data on an OUT endpoint, even if there is space in the RxFIFO to accommodate the incoming packet. -for non-isochronous IN endpoints: The core stops transmitting any data on an IN endpoint, even if there data is available in the TxFIFO. -for isochronous IN endpoints: The core sends out a zero-length data packet, even if there data is available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Naksts {
    #[doc = "0: `0`"]
    Nonnak = 0,
    #[doc = "1: `1`"]
    Nak = 1,
}
impl From<Naksts> for bool {
    #[inline(always)]
    fn from(variant: Naksts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `naksts` reader - When either the application or the core sets this bit: -The core stops receiving any data on an OUT endpoint, even if there is space in the RxFIFO to accommodate the incoming packet. -for non-isochronous IN endpoints: The core stops transmitting any data on an IN endpoint, even if there data is available in the TxFIFO. -for isochronous IN endpoints: The core sends out a zero-length data packet, even if there data is available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type NakstsR = crate::BitReader<Naksts>;
impl NakstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Naksts {
        match self.bits {
            false => Naksts::Nonnak,
            true => Naksts::Nak,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nonnak(&self) -> bool {
        *self == Naksts::Nonnak
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nak(&self) -> bool {
        *self == Naksts::Nak
    }
}
#[doc = "Field `naksts` writer - When either the application or the core sets this bit: -The core stops receiving any data on an OUT endpoint, even if there is space in the RxFIFO to accommodate the incoming packet. -for non-isochronous IN endpoints: The core stops transmitting any data on an IN endpoint, even if there data is available in the TxFIFO. -for isochronous IN endpoints: The core sends out a zero-length data packet, even if there data is available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type NakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is the transfer type supported by this logical endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Eptype {
    #[doc = "0: `0`"]
    Control = 0,
    #[doc = "1: `1`"]
    Isochronous = 1,
    #[doc = "2: `10`"]
    Bulk = 2,
    #[doc = "3: `11`"]
    Interrup = 3,
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
#[doc = "Field `eptype` reader - This is the transfer type supported by this logical endpoint."]
pub type EptypeR = crate::FieldReader<Eptype>;
impl EptypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eptype {
        match self.bits {
            0 => Eptype::Control,
            1 => Eptype::Isochronous,
            2 => Eptype::Bulk,
            3 => Eptype::Interrup,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_control(&self) -> bool {
        *self == Eptype::Control
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_isochronous(&self) -> bool {
        *self == Eptype::Isochronous
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_bulk(&self) -> bool {
        *self == Eptype::Bulk
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_interrup(&self) -> bool {
        *self == Eptype::Interrup
    }
}
#[doc = "Field `eptype` writer - This is the transfer type supported by this logical endpoint."]
pub type EptypeW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Eptype>;
impl<'a, REG> EptypeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn control(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Control)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn isochronous(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Isochronous)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn bulk(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Bulk)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn interrup(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Interrup)
    }
}
#[doc = "Applies to non-control, non-isochronous IN and OUT endpoints only. The application sets this bit to stall all tokens from the USB host to this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Only the application can clear this bit, never the core. Applies to control endpoints only. The application can only set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake.\n\nValue on reset: 0"]
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
#[doc = "Field `stall` reader - Applies to non-control, non-isochronous IN and OUT endpoints only. The application sets this bit to stall all tokens from the USB host to this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Only the application can clear this bit, never the core. Applies to control endpoints only. The application can only set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
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
#[doc = "Field `stall` writer - Applies to non-control, non-isochronous IN and OUT endpoints only. The application sets this bit to stall all tokens from the USB host to this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Only the application can clear this bit, never the core. Applies to control endpoints only. The application can only set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type StallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `txfnum` reader - Shared FIFO Operation-non-periodic endpoints must set this bit to zero. Periodic endpoints must map this to the corresponding Periodic TxFIFO number. 4'h0: Non-Periodic TxFIFO Others: Specified Periodic TxFIFO.number An interrupt IN endpoint can be configured as a non-periodic endpoint for applications such as mass storage. The core treats an IN endpoint as a non-periodic endpoint if the TxFNum field is set to 0. Configuring an interrupt IN endpoint as a non-periodic endpoint saves the extra periodic FIFO area. Dedicated FIFO Operation-these bits specify the FIFO number associated with this endpoint. Each active IN endpoint must be programmed to a separate FIFO number. This field is valid only for IN endpoints."]
pub type TxfnumR = crate::FieldReader;
#[doc = "Field `txfnum` writer - Shared FIFO Operation-non-periodic endpoints must set this bit to zero. Periodic endpoints must map this to the corresponding Periodic TxFIFO number. 4'h0: Non-Periodic TxFIFO Others: Specified Periodic TxFIFO.number An interrupt IN endpoint can be configured as a non-periodic endpoint for applications such as mass storage. The core treats an IN endpoint as a non-periodic endpoint if the TxFNum field is set to 0. Configuring an interrupt IN endpoint as a non-periodic endpoint saves the extra periodic FIFO area. Dedicated FIFO Operation-these bits specify the FIFO number associated with this endpoint. Each active IN endpoint must be programmed to a separate FIFO number. This field is valid only for IN endpoints."]
pub type TxfnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `cnak` reader - A write to this bit clears the NAK bit for the endpoint."]
pub type CnakR = crate::BitReader;
#[doc = "A write to this bit clears the NAK bit for the endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cnak {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
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
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Cnak::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Cnak::Active)
    }
}
#[doc = "Field `snak` reader - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
pub type SnakR = crate::BitReader;
#[doc = "A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Snak {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Snak> for bool {
    #[inline(always)]
    fn from(variant: Snak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `snak` writer - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
pub type SnakW<'a, REG> = crate::BitWriter<'a, REG, Snak>;
impl<'a, REG> SnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Snak::Inactive)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Snak::Active)
    }
}
#[doc = "Field `setd0pid` reader - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA0. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. In non-Scatter/Gather DMA mode: Set Even (micro)frame (SetEvenFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to even (micro) frame. When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is in the transmit descriptor structure. The frame in which to receive data is updated in receive descriptor structure."]
pub type Setd0pidR = crate::BitReader;
#[doc = "Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA0. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. In non-Scatter/Gather DMA mode: Set Even (micro)frame (SetEvenFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to even (micro) frame. When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is in the transmit descriptor structure. The frame in which to receive data is updated in receive descriptor structure.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setd0pid {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Setd0pid> for bool {
    #[inline(always)]
    fn from(variant: Setd0pid) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `setd0pid` writer - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA0. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. In non-Scatter/Gather DMA mode: Set Even (micro)frame (SetEvenFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to even (micro) frame. When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is in the transmit descriptor structure. The frame in which to receive data is updated in receive descriptor structure."]
pub type Setd0pidW<'a, REG> = crate::BitWriter<'a, REG, Setd0pid>;
impl<'a, REG> Setd0pidW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Setd0pid::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Setd0pid::Enabled)
    }
}
#[doc = "Field `setd1pid` reader - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA1. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Set Odd (micro)frame (SetOddFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to odd (micro)frame.This field is not applicable for Scatter/Gather DMA mode."]
pub type Setd1pidR = crate::BitReader;
#[doc = "Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA1. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Set Odd (micro)frame (SetOddFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to odd (micro)frame.This field is not applicable for Scatter/Gather DMA mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setd1pid {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Setd1pid> for bool {
    #[inline(always)]
    fn from(variant: Setd1pid) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `setd1pid` writer - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA1. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Set Odd (micro)frame (SetOddFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to odd (micro)frame.This field is not applicable for Scatter/Gather DMA mode."]
pub type Setd1pidW<'a, REG> = crate::BitWriter<'a, REG, Setd1pid>;
impl<'a, REG> Setd1pidW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Setd1pid::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Setd1pid::Enabled)
    }
}
#[doc = "Applies to IN and OUT endpoints. The application sets this bit to stop transmitting/receiving data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled interrupt. The application must set this bit only if Endpoint Enable is already set for this endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epdis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Epdis> for bool {
    #[inline(always)]
    fn from(variant: Epdis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epdis` reader - Applies to IN and OUT endpoints. The application sets this bit to stop transmitting/receiving data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled interrupt. The application must set this bit only if Endpoint Enable is already set for this endpoint."]
pub type EpdisR = crate::BitReader<Epdis>;
impl EpdisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epdis {
        match self.bits {
            false => Epdis::Inactive,
            true => Epdis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Epdis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Epdis::Active
    }
}
#[doc = "Field `epdis` writer - Applies to IN and OUT endpoints. The application sets this bit to stop transmitting/receiving data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled interrupt. The application must set this bit only if Endpoint Enable is already set for this endpoint."]
pub type EpdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to IN and OUT endpoints. -When Scatter/Gather DMA mode is enabled, -for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. -for OUT endpoint it indicates that the descriptor structure and data buffer to receive data is setup. -When Scatter/Gather DMA mode is enabled such as for buffer-pointer based DMA mode: - for IN endpoints, this bit indicates that data is ready to be transmitted on the endpoint. - for OUT endpoints, this bit indicates that the application has allocated the memory to start receiving data from the USB. - The core clears this bit before setting any of the following interrupts on this endpoint: -SETUP Phase Done -Endpoint Disabled -Transfer Completed for control endpoints in DMA mode, this bit must be set to be able to transfer SETUP data packets in memory.\n\nValue on reset: 0"]
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
#[doc = "Field `epena` reader - Applies to IN and OUT endpoints. -When Scatter/Gather DMA mode is enabled, -for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. -for OUT endpoint it indicates that the descriptor structure and data buffer to receive data is setup. -When Scatter/Gather DMA mode is enabled such as for buffer-pointer based DMA mode: - for IN endpoints, this bit indicates that data is ready to be transmitted on the endpoint. - for OUT endpoints, this bit indicates that the application has allocated the memory to start receiving data from the USB. - The core clears this bit before setting any of the following interrupts on this endpoint: -SETUP Phase Done -Endpoint Disabled -Transfer Completed for control endpoints in DMA mode, this bit must be set to be able to transfer SETUP data packets in memory."]
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
#[doc = "Field `epena` writer - Applies to IN and OUT endpoints. -When Scatter/Gather DMA mode is enabled, -for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. -for OUT endpoint it indicates that the descriptor structure and data buffer to receive data is setup. -When Scatter/Gather DMA mode is enabled such as for buffer-pointer based DMA mode: - for IN endpoints, this bit indicates that data is ready to be transmitted on the endpoint. - for OUT endpoints, this bit indicates that the application has allocated the memory to start receiving data from the USB. - The core clears this bit before setting any of the following interrupts on this endpoint: -SETUP Phase Done -Endpoint Disabled -Transfer Completed for control endpoints in DMA mode, this bit must be set to be able to transfer SETUP data packets in memory."]
pub type EpenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:10 - Applies to IN and OUT endpoints. The application must program this field with the maximum packet size for the current logical endpoint. This value is in bytes."]
    #[inline(always)]
    pub fn mps(&self) -> MpsR {
        MpsR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bit 15 - Indicates whether this endpoint is active in the current configuration and interface. The core clears this bit for all endpoints (other than EP 0) after detecting a USB reset. After receiving the SetConfiguration and SetInterface commands, the application must program endpoint registers accordingly and set this bit."]
    #[inline(always)]
    pub fn usbactep(&self) -> UsbactepR {
        UsbactepR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Applies to interrupt/bulk IN and OUT endpoints only. Contains the PID of the packet to be received or transmitted on this endpoint. The application must program the PID of the first packet to be received or transmitted on this endpoint, after the endpoint is activated. The applications use the SetD1PID and SetD0PID fields of this register to program either DATA0 or DATA1 PID. 0: DATA0 1: DATA1This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Even/Odd (Micro)Frame (EO_FrNum) In non-Scatter/Gather DMA mode: Applies to isochronous IN and OUT endpoints only. Indicates the (micro)frame number in which the core transmits/receives isochronous data for this endpoint. The application must program the even/odd (micro) frame number in which it intends to transmit/receive isochronous data for this endpoint using the SetEvnFr and SetOddFr fields in this register. 0: Even (micro)frame 1: Odd (micro)frame When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is provided in the transmit descriptor structure. The frame in which data is received is updated in receive descriptor structure."]
    #[inline(always)]
    pub fn dpid(&self) -> DpidR {
        DpidR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - When either the application or the core sets this bit: -The core stops receiving any data on an OUT endpoint, even if there is space in the RxFIFO to accommodate the incoming packet. -for non-isochronous IN endpoints: The core stops transmitting any data on an IN endpoint, even if there data is available in the TxFIFO. -for isochronous IN endpoints: The core sends out a zero-length data packet, even if there data is available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    pub fn naksts(&self) -> NakstsR {
        NakstsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - This is the transfer type supported by this logical endpoint."]
    #[inline(always)]
    pub fn eptype(&self) -> EptypeR {
        EptypeR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bit 21 - Applies to non-control, non-isochronous IN and OUT endpoints only. The application sets this bit to stall all tokens from the USB host to this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Only the application can clear this bit, never the core. Applies to control endpoints only. The application can only set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    pub fn stall(&self) -> StallR {
        StallR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bits 22:25 - Shared FIFO Operation-non-periodic endpoints must set this bit to zero. Periodic endpoints must map this to the corresponding Periodic TxFIFO number. 4'h0: Non-Periodic TxFIFO Others: Specified Periodic TxFIFO.number An interrupt IN endpoint can be configured as a non-periodic endpoint for applications such as mass storage. The core treats an IN endpoint as a non-periodic endpoint if the TxFNum field is set to 0. Configuring an interrupt IN endpoint as a non-periodic endpoint saves the extra periodic FIFO area. Dedicated FIFO Operation-these bits specify the FIFO number associated with this endpoint. Each active IN endpoint must be programmed to a separate FIFO number. This field is valid only for IN endpoints."]
    #[inline(always)]
    pub fn txfnum(&self) -> TxfnumR {
        TxfnumR::new(((self.bits >> 22) & 0x0f) as u8)
    }
    #[doc = "Bit 26 - A write to this bit clears the NAK bit for the endpoint."]
    #[inline(always)]
    pub fn cnak(&self) -> CnakR {
        CnakR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
    #[inline(always)]
    pub fn snak(&self) -> SnakR {
        SnakR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA0. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. In non-Scatter/Gather DMA mode: Set Even (micro)frame (SetEvenFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to even (micro) frame. When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is in the transmit descriptor structure. The frame in which to receive data is updated in receive descriptor structure."]
    #[inline(always)]
    pub fn setd0pid(&self) -> Setd0pidR {
        Setd0pidR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA1. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Set Odd (micro)frame (SetOddFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to odd (micro)frame.This field is not applicable for Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn setd1pid(&self) -> Setd1pidR {
        Setd1pidR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Applies to IN and OUT endpoints. The application sets this bit to stop transmitting/receiving data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled interrupt. The application must set this bit only if Endpoint Enable is already set for this endpoint."]
    #[inline(always)]
    pub fn epdis(&self) -> EpdisR {
        EpdisR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Applies to IN and OUT endpoints. -When Scatter/Gather DMA mode is enabled, -for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. -for OUT endpoint it indicates that the descriptor structure and data buffer to receive data is setup. -When Scatter/Gather DMA mode is enabled such as for buffer-pointer based DMA mode: - for IN endpoints, this bit indicates that data is ready to be transmitted on the endpoint. - for OUT endpoints, this bit indicates that the application has allocated the memory to start receiving data from the USB. - The core clears this bit before setting any of the following interrupts on this endpoint: -SETUP Phase Done -Endpoint Disabled -Transfer Completed for control endpoints in DMA mode, this bit must be set to be able to transfer SETUP data packets in memory."]
    #[inline(always)]
    pub fn epena(&self) -> EpenaR {
        EpenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:10 - Applies to IN and OUT endpoints. The application must program this field with the maximum packet size for the current logical endpoint. This value is in bytes."]
    #[inline(always)]
    #[must_use]
    pub fn mps(&mut self) -> MpsW<DevgrpDiepctl6Spec> {
        MpsW::new(self, 0)
    }
    #[doc = "Bit 15 - Indicates whether this endpoint is active in the current configuration and interface. The core clears this bit for all endpoints (other than EP 0) after detecting a USB reset. After receiving the SetConfiguration and SetInterface commands, the application must program endpoint registers accordingly and set this bit."]
    #[inline(always)]
    #[must_use]
    pub fn usbactep(&mut self) -> UsbactepW<DevgrpDiepctl6Spec> {
        UsbactepW::new(self, 15)
    }
    #[doc = "Bit 16 - Applies to interrupt/bulk IN and OUT endpoints only. Contains the PID of the packet to be received or transmitted on this endpoint. The application must program the PID of the first packet to be received or transmitted on this endpoint, after the endpoint is activated. The applications use the SetD1PID and SetD0PID fields of this register to program either DATA0 or DATA1 PID. 0: DATA0 1: DATA1This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Even/Odd (Micro)Frame (EO_FrNum) In non-Scatter/Gather DMA mode: Applies to isochronous IN and OUT endpoints only. Indicates the (micro)frame number in which the core transmits/receives isochronous data for this endpoint. The application must program the even/odd (micro) frame number in which it intends to transmit/receive isochronous data for this endpoint using the SetEvnFr and SetOddFr fields in this register. 0: Even (micro)frame 1: Odd (micro)frame When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is provided in the transmit descriptor structure. The frame in which data is received is updated in receive descriptor structure."]
    #[inline(always)]
    #[must_use]
    pub fn dpid(&mut self) -> DpidW<DevgrpDiepctl6Spec> {
        DpidW::new(self, 16)
    }
    #[doc = "Bit 17 - When either the application or the core sets this bit: -The core stops receiving any data on an OUT endpoint, even if there is space in the RxFIFO to accommodate the incoming packet. -for non-isochronous IN endpoints: The core stops transmitting any data on an IN endpoint, even if there data is available in the TxFIFO. -for isochronous IN endpoints: The core sends out a zero-length data packet, even if there data is available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    #[must_use]
    pub fn naksts(&mut self) -> NakstsW<DevgrpDiepctl6Spec> {
        NakstsW::new(self, 17)
    }
    #[doc = "Bits 18:19 - This is the transfer type supported by this logical endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn eptype(&mut self) -> EptypeW<DevgrpDiepctl6Spec> {
        EptypeW::new(self, 18)
    }
    #[doc = "Bit 21 - Applies to non-control, non-isochronous IN and OUT endpoints only. The application sets this bit to stall all tokens from the USB host to this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Only the application can clear this bit, never the core. Applies to control endpoints only. The application can only set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Non-periodic IN NAK, or Global OUT NAK is set along with this bit, the STALL bit takes priority. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    #[must_use]
    pub fn stall(&mut self) -> StallW<DevgrpDiepctl6Spec> {
        StallW::new(self, 21)
    }
    #[doc = "Bits 22:25 - Shared FIFO Operation-non-periodic endpoints must set this bit to zero. Periodic endpoints must map this to the corresponding Periodic TxFIFO number. 4'h0: Non-Periodic TxFIFO Others: Specified Periodic TxFIFO.number An interrupt IN endpoint can be configured as a non-periodic endpoint for applications such as mass storage. The core treats an IN endpoint as a non-periodic endpoint if the TxFNum field is set to 0. Configuring an interrupt IN endpoint as a non-periodic endpoint saves the extra periodic FIFO area. Dedicated FIFO Operation-these bits specify the FIFO number associated with this endpoint. Each active IN endpoint must be programmed to a separate FIFO number. This field is valid only for IN endpoints."]
    #[inline(always)]
    #[must_use]
    pub fn txfnum(&mut self) -> TxfnumW<DevgrpDiepctl6Spec> {
        TxfnumW::new(self, 22)
    }
    #[doc = "Bit 26 - A write to this bit clears the NAK bit for the endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn cnak(&mut self) -> CnakW<DevgrpDiepctl6Spec> {
        CnakW::new(self, 26)
    }
    #[doc = "Bit 27 - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn snak(&mut self) -> SnakW<DevgrpDiepctl6Spec> {
        SnakW::new(self, 27)
    }
    #[doc = "Bit 28 - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA0. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. In non-Scatter/Gather DMA mode: Set Even (micro)frame (SetEvenFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to even (micro) frame. When Scatter/Gather DMA mode is enabled, this field is reserved. The frame number in which to send data is in the transmit descriptor structure. The frame in which to receive data is updated in receive descriptor structure."]
    #[inline(always)]
    #[must_use]
    pub fn setd0pid(&mut self) -> Setd0pidW<DevgrpDiepctl6Spec> {
        Setd0pidW::new(self, 28)
    }
    #[doc = "Bit 29 - Applies to interrupt/bulk IN and OUT endpoints only. Writing to this field sets the Endpoint Data PID (DPID) field in this register to DATA1. This field is applicable both for Scatter/Gather DMA mode and non-Scatter/Gather DMA mode. Set Odd (micro)frame (SetOddFr) Applies to isochronous IN and OUT endpoints only. Writing to this field sets the Even/Odd (micro)frame (EO_FrNum) field to odd (micro)frame.This field is not applicable for Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn setd1pid(&mut self) -> Setd1pidW<DevgrpDiepctl6Spec> {
        Setd1pidW::new(self, 29)
    }
    #[doc = "Bit 30 - Applies to IN and OUT endpoints. The application sets this bit to stop transmitting/receiving data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled interrupt. The application must set this bit only if Endpoint Enable is already set for this endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn epdis(&mut self) -> EpdisW<DevgrpDiepctl6Spec> {
        EpdisW::new(self, 30)
    }
    #[doc = "Bit 31 - Applies to IN and OUT endpoints. -When Scatter/Gather DMA mode is enabled, -for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. -for OUT endpoint it indicates that the descriptor structure and data buffer to receive data is setup. -When Scatter/Gather DMA mode is enabled such as for buffer-pointer based DMA mode: - for IN endpoints, this bit indicates that data is ready to be transmitted on the endpoint. - for OUT endpoints, this bit indicates that the application has allocated the memory to start receiving data from the USB. - The core clears this bit before setting any of the following interrupts on this endpoint: -SETUP Phase Done -Endpoint Disabled -Transfer Completed for control endpoints in DMA mode, this bit must be set to be able to transfer SETUP data packets in memory."]
    #[inline(always)]
    #[must_use]
    pub fn epena(&mut self) -> EpenaW<DevgrpDiepctl6Spec> {
        EpenaW::new(self, 31)
    }
}
#[doc = "Endpoint_number: 6\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl6::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepctl6Spec;
impl crate::RegisterSpec for DevgrpDiepctl6Spec {
    type Ux = u32;
    const OFFSET: u64 = 2496u64;
}
#[doc = "`read()` method returns [`devgrp_diepctl6::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepctl6Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_diepctl6::W`](W) writer structure"]
impl crate::Writable for DevgrpDiepctl6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_diepctl6 to value 0"]
impl crate::Resettable for DevgrpDiepctl6Spec {
    const RESET_VALUE: u32 = 0;
}
