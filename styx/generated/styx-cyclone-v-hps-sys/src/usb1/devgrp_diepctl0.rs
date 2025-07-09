// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepctl0` reader"]
pub type R = crate::R<DevgrpDiepctl0Spec>;
#[doc = "Register `devgrp_diepctl0` writer"]
pub type W = crate::W<DevgrpDiepctl0Spec>;
#[doc = "Applies to IN and OUT endpoints.The application must program this field with the maximum packet size for the current logical endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mps {
    #[doc = "0: `0`"]
    Bytes64 = 0,
    #[doc = "1: `1`"]
    Bytes32 = 1,
    #[doc = "2: `10`"]
    Bytes16 = 2,
    #[doc = "3: `11`"]
    Bytes8 = 3,
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
#[doc = "Field `mps` reader - Applies to IN and OUT endpoints.The application must program this field with the maximum packet size for the current logical endpoint."]
pub type MpsR = crate::FieldReader<Mps>;
impl MpsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mps {
        match self.bits {
            0 => Mps::Bytes64,
            1 => Mps::Bytes32,
            2 => Mps::Bytes16,
            3 => Mps::Bytes8,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_bytes64(&self) -> bool {
        *self == Mps::Bytes64
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_bytes32(&self) -> bool {
        *self == Mps::Bytes32
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_bytes16(&self) -> bool {
        *self == Mps::Bytes16
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_bytes8(&self) -> bool {
        *self == Mps::Bytes8
    }
}
#[doc = "Field `mps` writer - Applies to IN and OUT endpoints.The application must program this field with the maximum packet size for the current logical endpoint."]
pub type MpsW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Mps>;
impl<'a, REG> MpsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn bytes64(self) -> &'a mut crate::W<REG> {
        self.variant(Mps::Bytes64)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn bytes32(self) -> &'a mut crate::W<REG> {
        self.variant(Mps::Bytes32)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn bytes16(self) -> &'a mut crate::W<REG> {
        self.variant(Mps::Bytes16)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn bytes8(self) -> &'a mut crate::W<REG> {
        self.variant(Mps::Bytes8)
    }
}
#[doc = "This bit is always SET to 1, indicating that control endpoint 0 is always active in all configurations and interfaces.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbactep {
    #[doc = "1: `1`"]
    Active0 = 1,
}
impl From<Usbactep> for bool {
    #[inline(always)]
    fn from(variant: Usbactep) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbactep` reader - This bit is always SET to 1, indicating that control endpoint 0 is always active in all configurations and interfaces."]
pub type UsbactepR = crate::BitReader<Usbactep>;
impl UsbactepR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Usbactep> {
        match self.bits {
            true => Some(Usbactep::Active0),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active0(&self) -> bool {
        *self == Usbactep::Active0
    }
}
#[doc = "Field `usbactep` writer - This bit is always SET to 1, indicating that control endpoint 0 is always active in all configurations and interfaces."]
pub type UsbactepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When this bit is Set, either by the application or core, the core stops transmitting data, even If there is data available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake.\n\nValue on reset: 0"]
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
#[doc = "Field `naksts` reader - When this bit is Set, either by the application or core, the core stops transmitting data, even If there is data available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
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
#[doc = "Field `naksts` writer - When this bit is Set, either by the application or core, the core stops transmitting data, even If there is data available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
pub type NakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Hardcoded to 00 for control.\n\nValue on reset: 0"]
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
#[doc = "Field `eptype` reader - Hardcoded to 00 for control."]
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
#[doc = "Field `eptype` writer - Hardcoded to 00 for control."]
pub type EptypeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Nonperiodic IN NAK, or Global OUT NAK is Set along with this bit, the STALL bit takes priority.\n\nValue on reset: 0"]
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
#[doc = "Field `stall` reader - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Nonperiodic IN NAK, or Global OUT NAK is Set along with this bit, the STALL bit takes priority."]
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
#[doc = "Field `stall` writer - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Nonperiodic IN NAK, or Global OUT NAK is Set along with this bit, the STALL bit takes priority."]
pub type StallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `txfnum` reader - for Shared FIFO operation, this value is always Set to 0, indicating that control IN endpoint 0 data is always written in the Non-Periodic Transmit FIFO. for Dedicated FIFO operation, this value is Set to the FIFO number that is assigned to IN Endpoint 0."]
pub type TxfnumR = crate::FieldReader;
#[doc = "Field `txfnum` writer - for Shared FIFO operation, this value is always Set to 0, indicating that control IN endpoint 0 data is always written in the Non-Periodic Transmit FIFO. for Dedicated FIFO operation, this value is Set to the FIFO number that is assigned to IN Endpoint 0."]
pub type TxfnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
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
#[doc = "Field `snak` reader - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
pub type SnakR = crate::BitReader;
#[doc = "A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint.\n\nValue on reset: 0"]
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
#[doc = "Field `snak` writer - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
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
#[doc = "The application sets this bit to stop transmitting data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled Interrupt. The application must Set this bit only If Endpoint Enable is already Set for this endpoint.\n\nValue on reset: 0"]
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
#[doc = "Field `epdis` reader - The application sets this bit to stop transmitting data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled Interrupt. The application must Set this bit only If Endpoint Enable is already Set for this endpoint."]
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
#[doc = "Field `epdis` writer - The application sets this bit to stop transmitting data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled Interrupt. The application must Set this bit only If Endpoint Enable is already Set for this endpoint."]
pub type EpdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When Scatter/Gather DMA mode is enabled, for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. When Scatter/Gather DMA mode is disabled such as in bufferpointer based DMA mode this bit indicates that data is ready to be transmitted on the endpoint. The core clears this bit before setting the following interrupts on this endpoint: -Endpoint Disabled -Transfer Completed\n\nValue on reset: 0"]
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
#[doc = "Field `epena` reader - When Scatter/Gather DMA mode is enabled, for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. When Scatter/Gather DMA mode is disabled such as in bufferpointer based DMA mode this bit indicates that data is ready to be transmitted on the endpoint. The core clears this bit before setting the following interrupts on this endpoint: -Endpoint Disabled -Transfer Completed"]
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
#[doc = "Field `epena` writer - When Scatter/Gather DMA mode is enabled, for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. When Scatter/Gather DMA mode is disabled such as in bufferpointer based DMA mode this bit indicates that data is ready to be transmitted on the endpoint. The core clears this bit before setting the following interrupts on this endpoint: -Endpoint Disabled -Transfer Completed"]
pub type EpenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - Applies to IN and OUT endpoints.The application must program this field with the maximum packet size for the current logical endpoint."]
    #[inline(always)]
    pub fn mps(&self) -> MpsR {
        MpsR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 15 - This bit is always SET to 1, indicating that control endpoint 0 is always active in all configurations and interfaces."]
    #[inline(always)]
    pub fn usbactep(&self) -> UsbactepR {
        UsbactepR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - When this bit is Set, either by the application or core, the core stops transmitting data, even If there is data available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    pub fn naksts(&self) -> NakstsR {
        NakstsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - Hardcoded to 00 for control."]
    #[inline(always)]
    pub fn eptype(&self) -> EptypeR {
        EptypeR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bit 21 - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Nonperiodic IN NAK, or Global OUT NAK is Set along with this bit, the STALL bit takes priority."]
    #[inline(always)]
    pub fn stall(&self) -> StallR {
        StallR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bits 22:25 - for Shared FIFO operation, this value is always Set to 0, indicating that control IN endpoint 0 data is always written in the Non-Periodic Transmit FIFO. for Dedicated FIFO operation, this value is Set to the FIFO number that is assigned to IN Endpoint 0."]
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
    #[doc = "Bit 30 - The application sets this bit to stop transmitting data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled Interrupt. The application must Set this bit only If Endpoint Enable is already Set for this endpoint."]
    #[inline(always)]
    pub fn epdis(&self) -> EpdisR {
        EpdisR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - When Scatter/Gather DMA mode is enabled, for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. When Scatter/Gather DMA mode is disabled such as in bufferpointer based DMA mode this bit indicates that data is ready to be transmitted on the endpoint. The core clears this bit before setting the following interrupts on this endpoint: -Endpoint Disabled -Transfer Completed"]
    #[inline(always)]
    pub fn epena(&self) -> EpenaR {
        EpenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - Applies to IN and OUT endpoints.The application must program this field with the maximum packet size for the current logical endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn mps(&mut self) -> MpsW<DevgrpDiepctl0Spec> {
        MpsW::new(self, 0)
    }
    #[doc = "Bit 15 - This bit is always SET to 1, indicating that control endpoint 0 is always active in all configurations and interfaces."]
    #[inline(always)]
    #[must_use]
    pub fn usbactep(&mut self) -> UsbactepW<DevgrpDiepctl0Spec> {
        UsbactepW::new(self, 15)
    }
    #[doc = "Bit 17 - When this bit is Set, either by the application or core, the core stops transmitting data, even If there is data available in the TxFIFO. Irrespective of this bit's setting, the core always responds to SETUP data packets with an ACK handshake."]
    #[inline(always)]
    #[must_use]
    pub fn naksts(&mut self) -> NakstsW<DevgrpDiepctl0Spec> {
        NakstsW::new(self, 17)
    }
    #[doc = "Bits 18:19 - Hardcoded to 00 for control."]
    #[inline(always)]
    #[must_use]
    pub fn eptype(&mut self) -> EptypeW<DevgrpDiepctl0Spec> {
        EptypeW::new(self, 18)
    }
    #[doc = "Bit 21 - The application can only Set this bit, and the core clears it, when a SETUP token is received for this endpoint. If a NAK bit, Global Nonperiodic IN NAK, or Global OUT NAK is Set along with this bit, the STALL bit takes priority."]
    #[inline(always)]
    #[must_use]
    pub fn stall(&mut self) -> StallW<DevgrpDiepctl0Spec> {
        StallW::new(self, 21)
    }
    #[doc = "Bits 22:25 - for Shared FIFO operation, this value is always Set to 0, indicating that control IN endpoint 0 data is always written in the Non-Periodic Transmit FIFO. for Dedicated FIFO operation, this value is Set to the FIFO number that is assigned to IN Endpoint 0."]
    #[inline(always)]
    #[must_use]
    pub fn txfnum(&mut self) -> TxfnumW<DevgrpDiepctl0Spec> {
        TxfnumW::new(self, 22)
    }
    #[doc = "Bit 26 - A write to this bit clears the NAK bit for the endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn cnak(&mut self) -> CnakW<DevgrpDiepctl0Spec> {
        CnakW::new(self, 26)
    }
    #[doc = "Bit 27 - A write to this bit sets the NAK bit for the endpoint. Using this bit, the application can control the transmission of NAK handshakes on an endpoint. The core can also Set this bit for an endpoint after a SETUP packet is received on that endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn snak(&mut self) -> SnakW<DevgrpDiepctl0Spec> {
        SnakW::new(self, 27)
    }
    #[doc = "Bit 30 - The application sets this bit to stop transmitting data on an endpoint, even before the transfer for that endpoint is complete. The application must wait for the Endpoint Disabled interrupt before treating the endpoint as disabled. The core clears this bit before setting the Endpoint Disabled Interrupt. The application must Set this bit only If Endpoint Enable is already Set for this endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn epdis(&mut self) -> EpdisW<DevgrpDiepctl0Spec> {
        EpdisW::new(self, 30)
    }
    #[doc = "Bit 31 - When Scatter/Gather DMA mode is enabled, for IN endpoints this bit indicates that the descriptor structure and data buffer with data ready to transmit is setup. When Scatter/Gather DMA mode is disabled such as in bufferpointer based DMA mode this bit indicates that data is ready to be transmitted on the endpoint. The core clears this bit before setting the following interrupts on this endpoint: -Endpoint Disabled -Transfer Completed"]
    #[inline(always)]
    #[must_use]
    pub fn epena(&mut self) -> EpenaW<DevgrpDiepctl0Spec> {
        EpenaW::new(self, 31)
    }
}
#[doc = "This register covers Device Control IN Endpoint 0.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepctl0Spec;
impl crate::RegisterSpec for DevgrpDiepctl0Spec {
    type Ux = u32;
    const OFFSET: u64 = 2304u64;
}
#[doc = "`read()` method returns [`devgrp_diepctl0::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepctl0Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_diepctl0::W`](W) writer structure"]
impl crate::Writable for DevgrpDiepctl0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_diepctl0 to value 0x8000"]
impl crate::Resettable for DevgrpDiepctl0Spec {
    const RESET_VALUE: u32 = 0x8000;
}
