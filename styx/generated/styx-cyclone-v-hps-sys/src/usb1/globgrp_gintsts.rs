// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_gintsts` reader"]
pub type R = crate::R<GlobgrpGintstsSpec>;
#[doc = "Register `globgrp_gintsts` writer"]
pub type W = crate::W<GlobgrpGintstsSpec>;
#[doc = "Mode: Host and Device. Indicates the current mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curmod {
    #[doc = "0: `0`"]
    Device = 0,
    #[doc = "1: `1`"]
    Host = 1,
}
impl From<Curmod> for bool {
    #[inline(always)]
    fn from(variant: Curmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `curmod` reader - Mode: Host and Device. Indicates the current mode."]
pub type CurmodR = crate::BitReader<Curmod>;
impl CurmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Curmod {
        match self.bits {
            false => Curmod::Device,
            true => Curmod::Host,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_device(&self) -> bool {
        *self == Curmod::Device
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_host(&self) -> bool {
        *self == Curmod::Host
    }
}
#[doc = "Field `curmod` writer - Mode: Host and Device. Indicates the current mode."]
pub type CurmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host and Device. The core sets this bit when the application is trying to access: -A Host mode register, when the core is operating in Device mode. -A Device mode register, when the core is operating in Host mode. The register access is completed on the AHB with an OKAYresponse, but is ignored by the core internally and does not affect the operation of the core. This bit can be set only by the core and the application should write 1 to clearit\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modemis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Modemis> for bool {
    #[inline(always)]
    fn from(variant: Modemis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `modemis` reader - Mode: Host and Device. The core sets this bit when the application is trying to access: -A Host mode register, when the core is operating in Device mode. -A Device mode register, when the core is operating in Host mode. The register access is completed on the AHB with an OKAYresponse, but is ignored by the core internally and does not affect the operation of the core. This bit can be set only by the core and the application should write 1 to clearit"]
pub type ModemisR = crate::BitReader<Modemis>;
impl ModemisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Modemis {
        match self.bits {
            false => Modemis::Inactive,
            true => Modemis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Modemis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Modemis::Active
    }
}
#[doc = "Field `modemis` writer - Mode: Host and Device. The core sets this bit when the application is trying to access: -A Host mode register, when the core is operating in Device mode. -A Device mode register, when the core is operating in Host mode. The register access is completed on the AHB with an OKAYresponse, but is ignored by the core internally and does not affect the operation of the core. This bit can be set only by the core and the application should write 1 to clearit"]
pub type ModemisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host and Device. The core sets this bit to indicate an OTG protocol event. The application must read the OTG Interrupt Status (GOTGINT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the GOTGINT register to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Otgint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Otgint> for bool {
    #[inline(always)]
    fn from(variant: Otgint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `otgint` reader - Mode: Host and Device. The core sets this bit to indicate an OTG protocol event. The application must read the OTG Interrupt Status (GOTGINT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the GOTGINT register to clear this bit."]
pub type OtgintR = crate::BitReader<Otgint>;
impl OtgintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Otgint {
        match self.bits {
            false => Otgint::Inactive,
            true => Otgint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Otgint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Otgint::Active
    }
}
#[doc = "Field `otgint` writer - Mode: Host and Device. The core sets this bit to indicate an OTG protocol event. The application must read the OTG Interrupt Status (GOTGINT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the GOTGINT register to clear this bit."]
pub type OtgintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host and Device. In Host mode, the core sets this bit to indicate that an SOF (FS), micro-SOF (HS), or Keep-Alive (LS) is transmitted on the USB. The application must write a 1 to this bit to clear the interrupt. In Device mode, the core sets this bit to indicate that an SOF token has been received on the USB. The application can read the Device Status register to get the current (micro)Frame number. This interrupt is seen only when the core is operating at either HS or FS. This bit can be set only by the core and the application should write 1 to clear it. This register may return 1 if read immediately after power on reset. If the register bit reads 1 immediately after power on reset it does not indicate that an SOF has been sent (in case of host mode) or SOF has been received (in case of device mode). The read value of this interrupt is valid only after a valid connection between host and device is established. If the bit is set after power on reset the application can clear the bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sof {
    #[doc = "0: `0`"]
    Intactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Sof> for bool {
    #[inline(always)]
    fn from(variant: Sof) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sof` reader - Mode: Host and Device. In Host mode, the core sets this bit to indicate that an SOF (FS), micro-SOF (HS), or Keep-Alive (LS) is transmitted on the USB. The application must write a 1 to this bit to clear the interrupt. In Device mode, the core sets this bit to indicate that an SOF token has been received on the USB. The application can read the Device Status register to get the current (micro)Frame number. This interrupt is seen only when the core is operating at either HS or FS. This bit can be set only by the core and the application should write 1 to clear it. This register may return 1 if read immediately after power on reset. If the register bit reads 1 immediately after power on reset it does not indicate that an SOF has been sent (in case of host mode) or SOF has been received (in case of device mode). The read value of this interrupt is valid only after a valid connection between host and device is established. If the bit is set after power on reset the application can clear the bit."]
pub type SofR = crate::BitReader<Sof>;
impl SofR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sof {
        match self.bits {
            false => Sof::Intactive,
            true => Sof::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_intactive(&self) -> bool {
        *self == Sof::Intactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Sof::Active
    }
}
#[doc = "Field `sof` writer - Mode: Host and Device. In Host mode, the core sets this bit to indicate that an SOF (FS), micro-SOF (HS), or Keep-Alive (LS) is transmitted on the USB. The application must write a 1 to this bit to clear the interrupt. In Device mode, the core sets this bit to indicate that an SOF token has been received on the USB. The application can read the Device Status register to get the current (micro)Frame number. This interrupt is seen only when the core is operating at either HS or FS. This bit can be set only by the core and the application should write 1 to clear it. This register may return 1 if read immediately after power on reset. If the register bit reads 1 immediately after power on reset it does not indicate that an SOF has been sent (in case of host mode) or SOF has been received (in case of device mode). The read value of this interrupt is valid only after a valid connection between host and device is established. If the bit is set after power on reset the application can clear the bit."]
pub type SofW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host and Device. Indicates that there is at least one packet pending to be read from the RxFIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxflvl {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxflvl> for bool {
    #[inline(always)]
    fn from(variant: Rxflvl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxflvl` reader - Mode: Host and Device. Indicates that there is at least one packet pending to be read from the RxFIFO."]
pub type RxflvlR = crate::BitReader<Rxflvl>;
impl RxflvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxflvl {
        match self.bits {
            false => Rxflvl::Inactive,
            true => Rxflvl::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxflvl::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxflvl::Active
    }
}
#[doc = "Field `rxflvl` writer - Mode: Host and Device. Indicates that there is at least one packet pending to be read from the RxFIFO."]
pub type RxflvlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. Indicates that the Set Global Non-periodic IN NAK bit in the Device Control register (DCTL.SGNPInNak), Set by the application, has taken effect in the core. That is, the core has sampled the Global IN NAK bit Set by the application. This bit can be cleared by clearing the Clear Global Non-periodic IN NAK bit in the Device Control register (DCTL.CGNPInNak). This interrupt does not necessarily mean that a NAK handshake is sent out on the USB. The STALL bit takes precedence over the NAK bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ginnakeff {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ginnakeff> for bool {
    #[inline(always)]
    fn from(variant: Ginnakeff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ginnakeff` reader - Mode: Device only. Indicates that the Set Global Non-periodic IN NAK bit in the Device Control register (DCTL.SGNPInNak), Set by the application, has taken effect in the core. That is, the core has sampled the Global IN NAK bit Set by the application. This bit can be cleared by clearing the Clear Global Non-periodic IN NAK bit in the Device Control register (DCTL.CGNPInNak). This interrupt does not necessarily mean that a NAK handshake is sent out on the USB. The STALL bit takes precedence over the NAK bit."]
pub type GinnakeffR = crate::BitReader<Ginnakeff>;
impl GinnakeffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ginnakeff {
        match self.bits {
            false => Ginnakeff::Inactive,
            true => Ginnakeff::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ginnakeff::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ginnakeff::Active
    }
}
#[doc = "Field `ginnakeff` writer - Mode: Device only. Indicates that the Set Global Non-periodic IN NAK bit in the Device Control register (DCTL.SGNPInNak), Set by the application, has taken effect in the core. That is, the core has sampled the Global IN NAK bit Set by the application. This bit can be cleared by clearing the Clear Global Non-periodic IN NAK bit in the Device Control register (DCTL.CGNPInNak). This interrupt does not necessarily mean that a NAK handshake is sent out on the USB. The STALL bit takes precedence over the NAK bit."]
pub type GinnakeffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. Indicates that the Set Global OUT NAK bit in the Device Control register (DCTL.SGOUTNak), Set by the application, has taken effect in the core. This bit can be cleared by writing the Clear Global OUT NAK bit in the Device Control register (DCTL.CGOUTNak).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Goutnakeff {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Goutnakeff> for bool {
    #[inline(always)]
    fn from(variant: Goutnakeff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `goutnakeff` reader - Mode: Device only. Indicates that the Set Global OUT NAK bit in the Device Control register (DCTL.SGOUTNak), Set by the application, has taken effect in the core. This bit can be cleared by writing the Clear Global OUT NAK bit in the Device Control register (DCTL.CGOUTNak)."]
pub type GoutnakeffR = crate::BitReader<Goutnakeff>;
impl GoutnakeffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Goutnakeff {
        match self.bits {
            false => Goutnakeff::Inactive,
            true => Goutnakeff::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Goutnakeff::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Goutnakeff::Active
    }
}
#[doc = "Field `goutnakeff` writer - Mode: Device only. Indicates that the Set Global OUT NAK bit in the Device Control register (DCTL.SGOUTNak), Set by the application, has taken effect in the core. This bit can be cleared by writing the Clear Global OUT NAK bit in the Device Control register (DCTL.CGOUTNak)."]
pub type GoutnakeffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit to indicate that an Idle state has been detected on the USB for 3 ms.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erlysusp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Erlysusp> for bool {
    #[inline(always)]
    fn from(variant: Erlysusp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `erlysusp` reader - Mode: Device only. The core sets this bit to indicate that an Idle state has been detected on the USB for 3 ms."]
pub type ErlysuspR = crate::BitReader<Erlysusp>;
impl ErlysuspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Erlysusp {
        match self.bits {
            false => Erlysusp::Inactive,
            true => Erlysusp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Erlysusp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Erlysusp::Active
    }
}
#[doc = "Field `erlysusp` writer - Mode: Device only. The core sets this bit to indicate that an Idle state has been detected on the USB for 3 ms."]
pub type ErlysuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit to indicate that a suspend was detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbsusp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Usbsusp> for bool {
    #[inline(always)]
    fn from(variant: Usbsusp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbsusp` reader - Mode: Device only. The core sets this bit to indicate that a suspend was detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time."]
pub type UsbsuspR = crate::BitReader<Usbsusp>;
impl UsbsuspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usbsusp {
        match self.bits {
            false => Usbsusp::Inactive,
            true => Usbsusp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Usbsusp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Usbsusp::Active
    }
}
#[doc = "Field `usbsusp` writer - Mode: Device only. The core sets this bit to indicate that a suspend was detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time."]
pub type UsbsuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit to indicate that a reset is detected on the USB.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usbrst {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Usbrst> for bool {
    #[inline(always)]
    fn from(variant: Usbrst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usbrst` reader - Mode: Device only. The core sets this bit to indicate that a reset is detected on the USB."]
pub type UsbrstR = crate::BitReader<Usbrst>;
impl UsbrstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usbrst {
        match self.bits {
            false => Usbrst::Inactive,
            true => Usbrst::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Usbrst::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Usbrst::Active
    }
}
#[doc = "Field `usbrst` writer - Mode: Device only. The core sets this bit to indicate that a reset is detected on the USB."]
pub type UsbrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit to indicate that speed enumeration is complete. The application must read the Device Status register to obtain the enumerated speed.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enumdone {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Enumdone> for bool {
    #[inline(always)]
    fn from(variant: Enumdone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enumdone` reader - Mode: Device only. The core sets this bit to indicate that speed enumeration is complete. The application must read the Device Status register to obtain the enumerated speed."]
pub type EnumdoneR = crate::BitReader<Enumdone>;
impl EnumdoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enumdone {
        match self.bits {
            false => Enumdone::Inactive,
            true => Enumdone::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Enumdone::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Enumdone::Active
    }
}
#[doc = "Field `enumdone` writer - Mode: Device only. The core sets this bit to indicate that speed enumeration is complete. The application must read the Device Status register to obtain the enumerated speed."]
pub type EnumdoneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit when it fails to write an isochronous OUT packet into the RxFIFO because the RxFIFO does not have enough space to accommodate a maximum packet size packet for the isochronous OUT endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isooutdrop {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Isooutdrop> for bool {
    #[inline(always)]
    fn from(variant: Isooutdrop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `isooutdrop` reader - Mode: Device only. The core sets this bit when it fails to write an isochronous OUT packet into the RxFIFO because the RxFIFO does not have enough space to accommodate a maximum packet size packet for the isochronous OUT endpoint."]
pub type IsooutdropR = crate::BitReader<Isooutdrop>;
impl IsooutdropR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Isooutdrop {
        match self.bits {
            false => Isooutdrop::Inactive,
            true => Isooutdrop::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Isooutdrop::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Isooutdrop::Active
    }
}
#[doc = "Field `isooutdrop` writer - Mode: Device only. The core sets this bit when it fails to write an isochronous OUT packet into the RxFIFO because the RxFIFO does not have enough space to accommodate a maximum packet size packet for the isochronous OUT endpoint."]
pub type IsooutdropW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. This interrupt is valid only in shared FIFO operation. Indicates that an IN token has been received for a non-periodic endpoint, but the data for another endpoint is present in the top of the Non-periodic Transmit FIFO and the IN endpoint mismatch count programmed by the application has expired.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epmis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Epmis> for bool {
    #[inline(always)]
    fn from(variant: Epmis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epmis` reader - Mode: Device only. This interrupt is valid only in shared FIFO operation. Indicates that an IN token has been received for a non-periodic endpoint, but the data for another endpoint is present in the top of the Non-periodic Transmit FIFO and the IN endpoint mismatch count programmed by the application has expired."]
pub type EpmisR = crate::BitReader<Epmis>;
impl EpmisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epmis {
        match self.bits {
            false => Epmis::Inactive,
            true => Epmis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Epmis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Epmis::Active
    }
}
#[doc = "Field `epmis` writer - Mode: Device only. This interrupt is valid only in shared FIFO operation. Indicates that an IN token has been received for a non-periodic endpoint, but the data for another endpoint is present in the top of the Non-periodic Transmit FIFO and the IN endpoint mismatch count programmed by the application has expired."]
pub type EpmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the IN endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the IN endpoint on Device IN Endpoint-n Interrupt (DIEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DIEPINTn register to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Iepint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Iepint> for bool {
    #[inline(always)]
    fn from(variant: Iepint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `iepint` reader - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the IN endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the IN endpoint on Device IN Endpoint-n Interrupt (DIEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DIEPINTn register to clear this bit."]
pub type IepintR = crate::BitReader<Iepint>;
impl IepintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Iepint {
        match self.bits {
            false => Iepint::Inactive,
            true => Iepint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Iepint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Iepint::Active
    }
}
#[doc = "Field `iepint` writer - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the IN endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the IN endpoint on Device IN Endpoint-n Interrupt (DIEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DIEPINTn register to clear this bit."]
pub type IepintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the OUT endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the OUT endpoint on which the interrupt occurred, and Then read the corresponding Device OUT Endpoint-n Interrupt (DOEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DOEPINTn register to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oepint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Oepint> for bool {
    #[inline(always)]
    fn from(variant: Oepint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `oepint` reader - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the OUT endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the OUT endpoint on which the interrupt occurred, and Then read the corresponding Device OUT Endpoint-n Interrupt (DOEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DOEPINTn register to clear this bit."]
pub type OepintR = crate::BitReader<Oepint>;
impl OepintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Oepint {
        match self.bits {
            false => Oepint::Inactive,
            true => Oepint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Oepint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Oepint::Active
    }
}
#[doc = "Field `oepint` writer - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the OUT endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the OUT endpoint on which the interrupt occurred, and Then read the corresponding Device OUT Endpoint-n Interrupt (DOEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DOEPINTn register to clear this bit."]
pub type OepintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The core sets this interrupt to indicate that there is at least isochronous IN endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This interrupt is not asserted in Scatter/Gather DMA mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incompisoin {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Incompisoin> for bool {
    #[inline(always)]
    fn from(variant: Incompisoin) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `incompisoin` reader - Mode: Device only. The core sets this interrupt to indicate that there is at least isochronous IN endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This interrupt is not asserted in Scatter/Gather DMA mode."]
pub type IncompisoinR = crate::BitReader<Incompisoin>;
impl IncompisoinR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Incompisoin {
        match self.bits {
            false => Incompisoin::Inactive,
            true => Incompisoin::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Incompisoin::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Incompisoin::Active
    }
}
#[doc = "Field `incompisoin` writer - Mode: Device only. The core sets this interrupt to indicate that there is at least isochronous IN endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This interrupt is not asserted in Scatter/Gather DMA mode."]
pub type IncompisoinW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. In Host mode, the core sets this interrupt bit when there are incomplete periodic transactions still pending which arescheduled for the current microframe. Incomplete Isochronous OUT Transfer (incompISOOUT) The Device mode, the core sets this interrupt to indicate that there is at least one isochronous OUT endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This bit can be set only by the core and the application should write 1 to clear it\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incomplp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Incomplp> for bool {
    #[inline(always)]
    fn from(variant: Incomplp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `incomplp` reader - Mode: Device only. In Host mode, the core sets this interrupt bit when there are incomplete periodic transactions still pending which arescheduled for the current microframe. Incomplete Isochronous OUT Transfer (incompISOOUT) The Device mode, the core sets this interrupt to indicate that there is at least one isochronous OUT endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This bit can be set only by the core and the application should write 1 to clear it"]
pub type IncomplpR = crate::BitReader<Incomplp>;
impl IncomplpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Incomplp {
        match self.bits {
            false => Incomplp::Inactive,
            true => Incomplp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Incomplp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Incomplp::Active
    }
}
#[doc = "Field `incomplp` writer - Mode: Device only. In Host mode, the core sets this interrupt bit when there are incomplete periodic transactions still pending which arescheduled for the current microframe. Incomplete Isochronous OUT Transfer (incompISOOUT) The Device mode, the core sets this interrupt to indicate that there is at least one isochronous OUT endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This bit can be set only by the core and the application should write 1 to clear it"]
pub type IncomplpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. This interrupt is valid only in DMA mode. This interrupt indicates that the core has stopped fetching data for IN endpoints due to the unavailability of TxFIFO space or Request Queue space. This interrupt is used by the application for an endpoint mismatch algorithm. for example, after detecting an endpoint mismatch, the application: - Sets a Global non-periodic IN NAK handshake - Disables In endpoints - Flushes the FIFO - Determines the token sequence from the IN Token Sequence Learning Queue - Re-enables the endpoints - Clears the Global non-periodic IN NAK handshake If the Global non-periodic IN NAK is cleared, the core has not yet fetched data for the IN endpoint, and the IN token is received: the core generates an IN token received when FIFO empty interrupt. The OTG Then sends the host a NAK response. To avoid this scenario, the application can check the GINTSTS.FetSusp interrupt, which ensures that the FIFO is full before clearing a Global NAK handshake. Alternatively, the application can mask the \"IN token received when FIFO empty\" interrupt when clearing a Global IN NAKhandshake.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetsusp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Fetsusp> for bool {
    #[inline(always)]
    fn from(variant: Fetsusp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fetsusp` reader - Mode: Device only. This interrupt is valid only in DMA mode. This interrupt indicates that the core has stopped fetching data for IN endpoints due to the unavailability of TxFIFO space or Request Queue space. This interrupt is used by the application for an endpoint mismatch algorithm. for example, after detecting an endpoint mismatch, the application: - Sets a Global non-periodic IN NAK handshake - Disables In endpoints - Flushes the FIFO - Determines the token sequence from the IN Token Sequence Learning Queue - Re-enables the endpoints - Clears the Global non-periodic IN NAK handshake If the Global non-periodic IN NAK is cleared, the core has not yet fetched data for the IN endpoint, and the IN token is received: the core generates an IN token received when FIFO empty interrupt. The OTG Then sends the host a NAK response. To avoid this scenario, the application can check the GINTSTS.FetSusp interrupt, which ensures that the FIFO is full before clearing a Global NAK handshake. Alternatively, the application can mask the \"IN token received when FIFO empty\" interrupt when clearing a Global IN NAKhandshake."]
pub type FetsuspR = crate::BitReader<Fetsusp>;
impl FetsuspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fetsusp {
        match self.bits {
            false => Fetsusp::Inactive,
            true => Fetsusp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Fetsusp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Fetsusp::Active
    }
}
#[doc = "Field `fetsusp` writer - Mode: Device only. This interrupt is valid only in DMA mode. This interrupt indicates that the core has stopped fetching data for IN endpoints due to the unavailability of TxFIFO space or Request Queue space. This interrupt is used by the application for an endpoint mismatch algorithm. for example, after detecting an endpoint mismatch, the application: - Sets a Global non-periodic IN NAK handshake - Disables In endpoints - Flushes the FIFO - Determines the token sequence from the IN Token Sequence Learning Queue - Re-enables the endpoints - Clears the Global non-periodic IN NAK handshake If the Global non-periodic IN NAK is cleared, the core has not yet fetched data for the IN endpoint, and the IN token is received: the core generates an IN token received when FIFO empty interrupt. The OTG Then sends the host a NAK response. To avoid this scenario, the application can check the GINTSTS.FetSusp interrupt, which ensures that the FIFO is full before clearing a Global NAK handshake. Alternatively, the application can mask the \"IN token received when FIFO empty\" interrupt when clearing a Global IN NAKhandshake."]
pub type FetsuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. In Device mode, this interrupt is asserted when a reset is detected on the USB in partial power-down mode when the device is in Suspend. In Host mode, this interrupt is not asserted.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resetdet {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Resetdet> for bool {
    #[inline(always)]
    fn from(variant: Resetdet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `resetdet` reader - Mode: Device only. In Device mode, this interrupt is asserted when a reset is detected on the USB in partial power-down mode when the device is in Suspend. In Host mode, this interrupt is not asserted."]
pub type ResetdetR = crate::BitReader<Resetdet>;
impl ResetdetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Resetdet {
        match self.bits {
            false => Resetdet::Inactive,
            true => Resetdet::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Resetdet::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Resetdet::Active
    }
}
#[doc = "Field `resetdet` writer - Mode: Device only. In Device mode, this interrupt is asserted when a reset is detected on the USB in partial power-down mode when the device is in Suspend. In Host mode, this interrupt is not asserted."]
pub type ResetdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host only. The core sets this bit to indicate a change in port status of one of the otg core ports in Host mode. The application must read the Host Port Control and Status (HPRT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the Host PC Control and Status register to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prtint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Prtint> for bool {
    #[inline(always)]
    fn from(variant: Prtint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prtint` reader - Mode:Host only. The core sets this bit to indicate a change in port status of one of the otg core ports in Host mode. The application must read the Host Port Control and Status (HPRT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the Host PC Control and Status register to clear this bit."]
pub type PrtintR = crate::BitReader<Prtint>;
impl PrtintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prtint {
        match self.bits {
            false => Prtint::Inactive,
            true => Prtint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Prtint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Prtint::Active
    }
}
#[doc = "Field `prtint` writer - Mode:Host only. The core sets this bit to indicate a change in port status of one of the otg core ports in Host mode. The application must read the Host Port Control and Status (HPRT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the Host PC Control and Status register to clear this bit."]
pub type PrtintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host only. The core sets this bit to indicate that an interrupt is pending on one of the channels of the core (in Host mode). The application must read the Host All Channels Interrupt (HAINT) register to determine the exact number of the channel on which the interrupt occurred, and Then read the corresponding Host Channel-n Interrupt (HCINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the HCINTn register to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hchint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Hchint> for bool {
    #[inline(always)]
    fn from(variant: Hchint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hchint` reader - Mode:Host only. The core sets this bit to indicate that an interrupt is pending on one of the channels of the core (in Host mode). The application must read the Host All Channels Interrupt (HAINT) register to determine the exact number of the channel on which the interrupt occurred, and Then read the corresponding Host Channel-n Interrupt (HCINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the HCINTn register to clear this bit."]
pub type HchintR = crate::BitReader<Hchint>;
impl HchintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hchint {
        match self.bits {
            false => Hchint::Inactive,
            true => Hchint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Hchint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Hchint::Active
    }
}
#[doc = "Field `hchint` writer - Mode:Host only. The core sets this bit to indicate that an interrupt is pending on one of the channels of the core (in Host mode). The application must read the Host All Channels Interrupt (HAINT) register to determine the exact number of the channel on which the interrupt occurred, and Then read the corresponding Host Channel-n Interrupt (HCINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the HCINTn register to clear this bit."]
pub type HchintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host only. This interrupt is asserted when the Periodic Transmit FIFO is either half or completely empty and there is space for at least one entry to be written in the Periodic Request Queue. The half or completely empty status is determined by the Periodic TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.PTxFEmpLvl).\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ptxfemp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ptxfemp> for bool {
    #[inline(always)]
    fn from(variant: Ptxfemp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ptxfemp` reader - Mode:Host only. This interrupt is asserted when the Periodic Transmit FIFO is either half or completely empty and there is space for at least one entry to be written in the Periodic Request Queue. The half or completely empty status is determined by the Periodic TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.PTxFEmpLvl)."]
pub type PtxfempR = crate::BitReader<Ptxfemp>;
impl PtxfempR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ptxfemp {
        match self.bits {
            false => Ptxfemp::Inactive,
            true => Ptxfemp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ptxfemp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ptxfemp::Active
    }
}
#[doc = "Field `ptxfemp` writer - Mode:Host only. This interrupt is asserted when the Periodic Transmit FIFO is either half or completely empty and there is space for at least one entry to be written in the Periodic Request Queue. The half or completely empty status is determined by the Periodic TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.PTxFEmpLvl)."]
pub type PtxfempW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The core sets this bit when there is a change in connector ID status. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConIdstsChng {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<ConIdstsChng> for bool {
    #[inline(always)]
    fn from(variant: ConIdstsChng) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ConIDStsChng` reader - Mode:Host and Device. The core sets this bit when there is a change in connector ID status. This bit can be set only by the core and the application should write 1 to clear it."]
pub type ConIdstsChngR = crate::BitReader<ConIdstsChng>;
impl ConIdstsChngR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> ConIdstsChng {
        match self.bits {
            false => ConIdstsChng::Inactive,
            true => ConIdstsChng::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == ConIdstsChng::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == ConIdstsChng::Active
    }
}
#[doc = "Field `ConIDStsChng` writer - Mode:Host and Device. The core sets this bit when there is a change in connector ID status. This bit can be set only by the core and the application should write 1 to clear it."]
pub type ConIdstsChngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host only. Asserted when a device disconnect is detected. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disconnint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Disconnint> for bool {
    #[inline(always)]
    fn from(variant: Disconnint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `disconnint` reader - Mode:Host only. Asserted when a device disconnect is detected. This bit can be set only by the core and the application should write 1 to clear it."]
pub type DisconnintR = crate::BitReader<Disconnint>;
impl DisconnintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Disconnint {
        match self.bits {
            false => Disconnint::Inactive,
            true => Disconnint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Disconnint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Disconnint::Active
    }
}
#[doc = "Field `disconnint` writer - Mode:Host only. Asserted when a device disconnect is detected. This bit can be set only by the core and the application should write 1 to clear it."]
pub type DisconnintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Device mode, this interrupt is asserted when the utmisrp_bvalid signal goes high. This bit can be set only by the core and the application should write 1 to clear.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sessreqint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Sessreqint> for bool {
    #[inline(always)]
    fn from(variant: Sessreqint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sessreqint` reader - Mode:Host and Device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Device mode, this interrupt is asserted when the utmisrp_bvalid signal goes high. This bit can be set only by the core and the application should write 1 to clear."]
pub type SessreqintR = crate::BitReader<Sessreqint>;
impl SessreqintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sessreqint {
        match self.bits {
            false => Sessreqint::Inactive,
            true => Sessreqint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Sessreqint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Sessreqint::Active
    }
}
#[doc = "Field `sessreqint` writer - Mode:Host and Device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Device mode, this interrupt is asserted when the utmisrp_bvalid signal goes high. This bit can be set only by the core and the application should write 1 to clear."]
pub type SessreqintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. Wakeup Interrupt during Suspend(L2) or LPM(L1) state. -During Suspend(L2): - Device Mode - This interrupt is asserted only when Host Initiated Resume is detected on USB. - Host Mode - This interrupt is asserted only when Device Initiated Remote Wakeup is detected on USB - During LPM(L1):- - Device Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB. - Host Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wkupint {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Wkupint> for bool {
    #[inline(always)]
    fn from(variant: Wkupint) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wkupint` reader - Mode:Host and Device. Wakeup Interrupt during Suspend(L2) or LPM(L1) state. -During Suspend(L2): - Device Mode - This interrupt is asserted only when Host Initiated Resume is detected on USB. - Host Mode - This interrupt is asserted only when Device Initiated Remote Wakeup is detected on USB - During LPM(L1):- - Device Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB. - Host Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB."]
pub type WkupintR = crate::BitReader<Wkupint>;
impl WkupintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wkupint {
        match self.bits {
            false => Wkupint::Inactive,
            true => Wkupint::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Wkupint::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Wkupint::Active
    }
}
#[doc = "Field `wkupint` writer - Mode:Host and Device. Wakeup Interrupt during Suspend(L2) or LPM(L1) state. -During Suspend(L2): - Device Mode - This interrupt is asserted only when Host Initiated Resume is detected on USB. - Host Mode - This interrupt is asserted only when Device Initiated Remote Wakeup is detected on USB - During LPM(L1):- - Device Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB. - Host Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB."]
pub type WkupintW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Mode: Host and Device. Indicates the current mode."]
    #[inline(always)]
    pub fn curmod(&self) -> CurmodR {
        CurmodR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mode: Host and Device. The core sets this bit when the application is trying to access: -A Host mode register, when the core is operating in Device mode. -A Device mode register, when the core is operating in Host mode. The register access is completed on the AHB with an OKAYresponse, but is ignored by the core internally and does not affect the operation of the core. This bit can be set only by the core and the application should write 1 to clearit"]
    #[inline(always)]
    pub fn modemis(&self) -> ModemisR {
        ModemisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Mode: Host and Device. The core sets this bit to indicate an OTG protocol event. The application must read the OTG Interrupt Status (GOTGINT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the GOTGINT register to clear this bit."]
    #[inline(always)]
    pub fn otgint(&self) -> OtgintR {
        OtgintR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Mode: Host and Device. In Host mode, the core sets this bit to indicate that an SOF (FS), micro-SOF (HS), or Keep-Alive (LS) is transmitted on the USB. The application must write a 1 to this bit to clear the interrupt. In Device mode, the core sets this bit to indicate that an SOF token has been received on the USB. The application can read the Device Status register to get the current (micro)Frame number. This interrupt is seen only when the core is operating at either HS or FS. This bit can be set only by the core and the application should write 1 to clear it. This register may return 1 if read immediately after power on reset. If the register bit reads 1 immediately after power on reset it does not indicate that an SOF has been sent (in case of host mode) or SOF has been received (in case of device mode). The read value of this interrupt is valid only after a valid connection between host and device is established. If the bit is set after power on reset the application can clear the bit."]
    #[inline(always)]
    pub fn sof(&self) -> SofR {
        SofR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Mode: Host and Device. Indicates that there is at least one packet pending to be read from the RxFIFO."]
    #[inline(always)]
    pub fn rxflvl(&self) -> RxflvlR {
        RxflvlR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Mode: Device only. Indicates that the Set Global Non-periodic IN NAK bit in the Device Control register (DCTL.SGNPInNak), Set by the application, has taken effect in the core. That is, the core has sampled the Global IN NAK bit Set by the application. This bit can be cleared by clearing the Clear Global Non-periodic IN NAK bit in the Device Control register (DCTL.CGNPInNak). This interrupt does not necessarily mean that a NAK handshake is sent out on the USB. The STALL bit takes precedence over the NAK bit."]
    #[inline(always)]
    pub fn ginnakeff(&self) -> GinnakeffR {
        GinnakeffR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Mode: Device only. Indicates that the Set Global OUT NAK bit in the Device Control register (DCTL.SGOUTNak), Set by the application, has taken effect in the core. This bit can be cleared by writing the Clear Global OUT NAK bit in the Device Control register (DCTL.CGOUTNak)."]
    #[inline(always)]
    pub fn goutnakeff(&self) -> GoutnakeffR {
        GoutnakeffR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 10 - Mode: Device only. The core sets this bit to indicate that an Idle state has been detected on the USB for 3 ms."]
    #[inline(always)]
    pub fn erlysusp(&self) -> ErlysuspR {
        ErlysuspR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Mode: Device only. The core sets this bit to indicate that a suspend was detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time."]
    #[inline(always)]
    pub fn usbsusp(&self) -> UsbsuspR {
        UsbsuspR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Mode: Device only. The core sets this bit to indicate that a reset is detected on the USB."]
    #[inline(always)]
    pub fn usbrst(&self) -> UsbrstR {
        UsbrstR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Mode: Device only. The core sets this bit to indicate that speed enumeration is complete. The application must read the Device Status register to obtain the enumerated speed."]
    #[inline(always)]
    pub fn enumdone(&self) -> EnumdoneR {
        EnumdoneR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Mode: Device only. The core sets this bit when it fails to write an isochronous OUT packet into the RxFIFO because the RxFIFO does not have enough space to accommodate a maximum packet size packet for the isochronous OUT endpoint."]
    #[inline(always)]
    pub fn isooutdrop(&self) -> IsooutdropR {
        IsooutdropR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 17 - Mode: Device only. This interrupt is valid only in shared FIFO operation. Indicates that an IN token has been received for a non-periodic endpoint, but the data for another endpoint is present in the top of the Non-periodic Transmit FIFO and the IN endpoint mismatch count programmed by the application has expired."]
    #[inline(always)]
    pub fn epmis(&self) -> EpmisR {
        EpmisR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the IN endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the IN endpoint on Device IN Endpoint-n Interrupt (DIEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DIEPINTn register to clear this bit."]
    #[inline(always)]
    pub fn iepint(&self) -> IepintR {
        IepintR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the OUT endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the OUT endpoint on which the interrupt occurred, and Then read the corresponding Device OUT Endpoint-n Interrupt (DOEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DOEPINTn register to clear this bit."]
    #[inline(always)]
    pub fn oepint(&self) -> OepintR {
        OepintR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Mode: Device only. The core sets this interrupt to indicate that there is at least isochronous IN endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This interrupt is not asserted in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn incompisoin(&self) -> IncompisoinR {
        IncompisoinR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Mode: Device only. In Host mode, the core sets this interrupt bit when there are incomplete periodic transactions still pending which arescheduled for the current microframe. Incomplete Isochronous OUT Transfer (incompISOOUT) The Device mode, the core sets this interrupt to indicate that there is at least one isochronous OUT endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This bit can be set only by the core and the application should write 1 to clear it"]
    #[inline(always)]
    pub fn incomplp(&self) -> IncomplpR {
        IncomplpR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Mode: Device only. This interrupt is valid only in DMA mode. This interrupt indicates that the core has stopped fetching data for IN endpoints due to the unavailability of TxFIFO space or Request Queue space. This interrupt is used by the application for an endpoint mismatch algorithm. for example, after detecting an endpoint mismatch, the application: - Sets a Global non-periodic IN NAK handshake - Disables In endpoints - Flushes the FIFO - Determines the token sequence from the IN Token Sequence Learning Queue - Re-enables the endpoints - Clears the Global non-periodic IN NAK handshake If the Global non-periodic IN NAK is cleared, the core has not yet fetched data for the IN endpoint, and the IN token is received: the core generates an IN token received when FIFO empty interrupt. The OTG Then sends the host a NAK response. To avoid this scenario, the application can check the GINTSTS.FetSusp interrupt, which ensures that the FIFO is full before clearing a Global NAK handshake. Alternatively, the application can mask the \"IN token received when FIFO empty\" interrupt when clearing a Global IN NAKhandshake."]
    #[inline(always)]
    pub fn fetsusp(&self) -> FetsuspR {
        FetsuspR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Mode: Device only. In Device mode, this interrupt is asserted when a reset is detected on the USB in partial power-down mode when the device is in Suspend. In Host mode, this interrupt is not asserted."]
    #[inline(always)]
    pub fn resetdet(&self) -> ResetdetR {
        ResetdetR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Mode:Host only. The core sets this bit to indicate a change in port status of one of the otg core ports in Host mode. The application must read the Host Port Control and Status (HPRT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the Host PC Control and Status register to clear this bit."]
    #[inline(always)]
    pub fn prtint(&self) -> PrtintR {
        PrtintR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Mode:Host only. The core sets this bit to indicate that an interrupt is pending on one of the channels of the core (in Host mode). The application must read the Host All Channels Interrupt (HAINT) register to determine the exact number of the channel on which the interrupt occurred, and Then read the corresponding Host Channel-n Interrupt (HCINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the HCINTn register to clear this bit."]
    #[inline(always)]
    pub fn hchint(&self) -> HchintR {
        HchintR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Mode:Host only. This interrupt is asserted when the Periodic Transmit FIFO is either half or completely empty and there is space for at least one entry to be written in the Periodic Request Queue. The half or completely empty status is determined by the Periodic TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.PTxFEmpLvl)."]
    #[inline(always)]
    pub fn ptxfemp(&self) -> PtxfempR {
        PtxfempR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Mode:Host and Device. The core sets this bit when there is a change in connector ID status. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn con_idsts_chng(&self) -> ConIdstsChngR {
        ConIdstsChngR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Mode:Host only. Asserted when a device disconnect is detected. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn disconnint(&self) -> DisconnintR {
        DisconnintR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Mode:Host and Device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Device mode, this interrupt is asserted when the utmisrp_bvalid signal goes high. This bit can be set only by the core and the application should write 1 to clear."]
    #[inline(always)]
    pub fn sessreqint(&self) -> SessreqintR {
        SessreqintR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Mode:Host and Device. Wakeup Interrupt during Suspend(L2) or LPM(L1) state. -During Suspend(L2): - Device Mode - This interrupt is asserted only when Host Initiated Resume is detected on USB. - Host Mode - This interrupt is asserted only when Device Initiated Remote Wakeup is detected on USB - During LPM(L1):- - Device Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB. - Host Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB."]
    #[inline(always)]
    pub fn wkupint(&self) -> WkupintR {
        WkupintR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Mode: Host and Device. Indicates the current mode."]
    #[inline(always)]
    #[must_use]
    pub fn curmod(&mut self) -> CurmodW<GlobgrpGintstsSpec> {
        CurmodW::new(self, 0)
    }
    #[doc = "Bit 1 - Mode: Host and Device. The core sets this bit when the application is trying to access: -A Host mode register, when the core is operating in Device mode. -A Device mode register, when the core is operating in Host mode. The register access is completed on the AHB with an OKAYresponse, but is ignored by the core internally and does not affect the operation of the core. This bit can be set only by the core and the application should write 1 to clearit"]
    #[inline(always)]
    #[must_use]
    pub fn modemis(&mut self) -> ModemisW<GlobgrpGintstsSpec> {
        ModemisW::new(self, 1)
    }
    #[doc = "Bit 2 - Mode: Host and Device. The core sets this bit to indicate an OTG protocol event. The application must read the OTG Interrupt Status (GOTGINT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the GOTGINT register to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn otgint(&mut self) -> OtgintW<GlobgrpGintstsSpec> {
        OtgintW::new(self, 2)
    }
    #[doc = "Bit 3 - Mode: Host and Device. In Host mode, the core sets this bit to indicate that an SOF (FS), micro-SOF (HS), or Keep-Alive (LS) is transmitted on the USB. The application must write a 1 to this bit to clear the interrupt. In Device mode, the core sets this bit to indicate that an SOF token has been received on the USB. The application can read the Device Status register to get the current (micro)Frame number. This interrupt is seen only when the core is operating at either HS or FS. This bit can be set only by the core and the application should write 1 to clear it. This register may return 1 if read immediately after power on reset. If the register bit reads 1 immediately after power on reset it does not indicate that an SOF has been sent (in case of host mode) or SOF has been received (in case of device mode). The read value of this interrupt is valid only after a valid connection between host and device is established. If the bit is set after power on reset the application can clear the bit."]
    #[inline(always)]
    #[must_use]
    pub fn sof(&mut self) -> SofW<GlobgrpGintstsSpec> {
        SofW::new(self, 3)
    }
    #[doc = "Bit 4 - Mode: Host and Device. Indicates that there is at least one packet pending to be read from the RxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rxflvl(&mut self) -> RxflvlW<GlobgrpGintstsSpec> {
        RxflvlW::new(self, 4)
    }
    #[doc = "Bit 6 - Mode: Device only. Indicates that the Set Global Non-periodic IN NAK bit in the Device Control register (DCTL.SGNPInNak), Set by the application, has taken effect in the core. That is, the core has sampled the Global IN NAK bit Set by the application. This bit can be cleared by clearing the Clear Global Non-periodic IN NAK bit in the Device Control register (DCTL.CGNPInNak). This interrupt does not necessarily mean that a NAK handshake is sent out on the USB. The STALL bit takes precedence over the NAK bit."]
    #[inline(always)]
    #[must_use]
    pub fn ginnakeff(&mut self) -> GinnakeffW<GlobgrpGintstsSpec> {
        GinnakeffW::new(self, 6)
    }
    #[doc = "Bit 7 - Mode: Device only. Indicates that the Set Global OUT NAK bit in the Device Control register (DCTL.SGOUTNak), Set by the application, has taken effect in the core. This bit can be cleared by writing the Clear Global OUT NAK bit in the Device Control register (DCTL.CGOUTNak)."]
    #[inline(always)]
    #[must_use]
    pub fn goutnakeff(&mut self) -> GoutnakeffW<GlobgrpGintstsSpec> {
        GoutnakeffW::new(self, 7)
    }
    #[doc = "Bit 10 - Mode: Device only. The core sets this bit to indicate that an Idle state has been detected on the USB for 3 ms."]
    #[inline(always)]
    #[must_use]
    pub fn erlysusp(&mut self) -> ErlysuspW<GlobgrpGintstsSpec> {
        ErlysuspW::new(self, 10)
    }
    #[doc = "Bit 11 - Mode: Device only. The core sets this bit to indicate that a suspend was detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time."]
    #[inline(always)]
    #[must_use]
    pub fn usbsusp(&mut self) -> UsbsuspW<GlobgrpGintstsSpec> {
        UsbsuspW::new(self, 11)
    }
    #[doc = "Bit 12 - Mode: Device only. The core sets this bit to indicate that a reset is detected on the USB."]
    #[inline(always)]
    #[must_use]
    pub fn usbrst(&mut self) -> UsbrstW<GlobgrpGintstsSpec> {
        UsbrstW::new(self, 12)
    }
    #[doc = "Bit 13 - Mode: Device only. The core sets this bit to indicate that speed enumeration is complete. The application must read the Device Status register to obtain the enumerated speed."]
    #[inline(always)]
    #[must_use]
    pub fn enumdone(&mut self) -> EnumdoneW<GlobgrpGintstsSpec> {
        EnumdoneW::new(self, 13)
    }
    #[doc = "Bit 14 - Mode: Device only. The core sets this bit when it fails to write an isochronous OUT packet into the RxFIFO because the RxFIFO does not have enough space to accommodate a maximum packet size packet for the isochronous OUT endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn isooutdrop(&mut self) -> IsooutdropW<GlobgrpGintstsSpec> {
        IsooutdropW::new(self, 14)
    }
    #[doc = "Bit 17 - Mode: Device only. This interrupt is valid only in shared FIFO operation. Indicates that an IN token has been received for a non-periodic endpoint, but the data for another endpoint is present in the top of the Non-periodic Transmit FIFO and the IN endpoint mismatch count programmed by the application has expired."]
    #[inline(always)]
    #[must_use]
    pub fn epmis(&mut self) -> EpmisW<GlobgrpGintstsSpec> {
        EpmisW::new(self, 17)
    }
    #[doc = "Bit 18 - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the IN endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the IN endpoint on Device IN Endpoint-n Interrupt (DIEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DIEPINTn register to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn iepint(&mut self) -> IepintW<GlobgrpGintstsSpec> {
        IepintW::new(self, 18)
    }
    #[doc = "Bit 19 - Mode: Device only. The core sets this bit to indicate that an interrupt is pending on one of the OUT endpoints of the core (in Device mode). The application must read the Device All Endpoints Interrupt (DAINT) register to determine the exact number of the OUT endpoint on which the interrupt occurred, and Then read the corresponding Device OUT Endpoint-n Interrupt (DOEPINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the corresponding DOEPINTn register to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn oepint(&mut self) -> OepintW<GlobgrpGintstsSpec> {
        OepintW::new(self, 19)
    }
    #[doc = "Bit 20 - Mode: Device only. The core sets this interrupt to indicate that there is at least isochronous IN endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This interrupt is not asserted in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn incompisoin(&mut self) -> IncompisoinW<GlobgrpGintstsSpec> {
        IncompisoinW::new(self, 20)
    }
    #[doc = "Bit 21 - Mode: Device only. In Host mode, the core sets this interrupt bit when there are incomplete periodic transactions still pending which arescheduled for the current microframe. Incomplete Isochronous OUT Transfer (incompISOOUT) The Device mode, the core sets this interrupt to indicate that there is at least one isochronous OUT endpoint on which the transfer is not completed in the current microframe. This interrupt is asserted along with the End of Periodic Frame Interrupt (EOPF) bit in this register. This bit can be set only by the core and the application should write 1 to clear it"]
    #[inline(always)]
    #[must_use]
    pub fn incomplp(&mut self) -> IncomplpW<GlobgrpGintstsSpec> {
        IncomplpW::new(self, 21)
    }
    #[doc = "Bit 22 - Mode: Device only. This interrupt is valid only in DMA mode. This interrupt indicates that the core has stopped fetching data for IN endpoints due to the unavailability of TxFIFO space or Request Queue space. This interrupt is used by the application for an endpoint mismatch algorithm. for example, after detecting an endpoint mismatch, the application: - Sets a Global non-periodic IN NAK handshake - Disables In endpoints - Flushes the FIFO - Determines the token sequence from the IN Token Sequence Learning Queue - Re-enables the endpoints - Clears the Global non-periodic IN NAK handshake If the Global non-periodic IN NAK is cleared, the core has not yet fetched data for the IN endpoint, and the IN token is received: the core generates an IN token received when FIFO empty interrupt. The OTG Then sends the host a NAK response. To avoid this scenario, the application can check the GINTSTS.FetSusp interrupt, which ensures that the FIFO is full before clearing a Global NAK handshake. Alternatively, the application can mask the \"IN token received when FIFO empty\" interrupt when clearing a Global IN NAKhandshake."]
    #[inline(always)]
    #[must_use]
    pub fn fetsusp(&mut self) -> FetsuspW<GlobgrpGintstsSpec> {
        FetsuspW::new(self, 22)
    }
    #[doc = "Bit 23 - Mode: Device only. In Device mode, this interrupt is asserted when a reset is detected on the USB in partial power-down mode when the device is in Suspend. In Host mode, this interrupt is not asserted."]
    #[inline(always)]
    #[must_use]
    pub fn resetdet(&mut self) -> ResetdetW<GlobgrpGintstsSpec> {
        ResetdetW::new(self, 23)
    }
    #[doc = "Bit 24 - Mode:Host only. The core sets this bit to indicate a change in port status of one of the otg core ports in Host mode. The application must read the Host Port Control and Status (HPRT) register to determine the exact event that caused this interrupt. The application must clear the appropriate status bit in the Host PC Control and Status register to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn prtint(&mut self) -> PrtintW<GlobgrpGintstsSpec> {
        PrtintW::new(self, 24)
    }
    #[doc = "Bit 25 - Mode:Host only. The core sets this bit to indicate that an interrupt is pending on one of the channels of the core (in Host mode). The application must read the Host All Channels Interrupt (HAINT) register to determine the exact number of the channel on which the interrupt occurred, and Then read the corresponding Host Channel-n Interrupt (HCINTn) register to determine the exact cause of the interrupt. The application must clear the appropriate status bit in the HCINTn register to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn hchint(&mut self) -> HchintW<GlobgrpGintstsSpec> {
        HchintW::new(self, 25)
    }
    #[doc = "Bit 26 - Mode:Host only. This interrupt is asserted when the Periodic Transmit FIFO is either half or completely empty and there is space for at least one entry to be written in the Periodic Request Queue. The half or completely empty status is determined by the Periodic TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.PTxFEmpLvl)."]
    #[inline(always)]
    #[must_use]
    pub fn ptxfemp(&mut self) -> PtxfempW<GlobgrpGintstsSpec> {
        PtxfempW::new(self, 26)
    }
    #[doc = "Bit 28 - Mode:Host and Device. The core sets this bit when there is a change in connector ID status. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn con_idsts_chng(&mut self) -> ConIdstsChngW<GlobgrpGintstsSpec> {
        ConIdstsChngW::new(self, 28)
    }
    #[doc = "Bit 29 - Mode:Host only. Asserted when a device disconnect is detected. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn disconnint(&mut self) -> DisconnintW<GlobgrpGintstsSpec> {
        DisconnintW::new(self, 29)
    }
    #[doc = "Bit 30 - Mode:Host and Device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Host mode, this interrupt is asserted when a session request is detected from the device. In Device mode, this interrupt is asserted when the utmisrp_bvalid signal goes high. This bit can be set only by the core and the application should write 1 to clear."]
    #[inline(always)]
    #[must_use]
    pub fn sessreqint(&mut self) -> SessreqintW<GlobgrpGintstsSpec> {
        SessreqintW::new(self, 30)
    }
    #[doc = "Bit 31 - Mode:Host and Device. Wakeup Interrupt during Suspend(L2) or LPM(L1) state. -During Suspend(L2): - Device Mode - This interrupt is asserted only when Host Initiated Resume is detected on USB. - Host Mode - This interrupt is asserted only when Device Initiated Remote Wakeup is detected on USB - During LPM(L1):- - Device Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB. - Host Mode - This interrupt is asserted for either Host Initiated Resume or Device Initiated Remote Wakeup on USB."]
    #[inline(always)]
    #[must_use]
    pub fn wkupint(&mut self) -> WkupintW<GlobgrpGintstsSpec> {
        WkupintW::new(self, 31)
    }
}
#[doc = "This register interrupts the application for system-level events in the current mode (Device mode or Host mode). Some of the bits in this register are valid only in Host mode, while others are valid in Device mode only. This register also indicates the current mode. To clear the interrupt status bits of type R_SS_WC, the application must write 1 into the bit. The FIFO status interrupts are read only; once software reads from or writes to the FIFO while servicing these interrupts, FIFO interrupt conditions are cleared automatically. The application must clear the GINTSTS register at initialization before unmasking the interrupt bit to avoid any interrupts generated prior to initialization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gintsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGintstsSpec;
impl crate::RegisterSpec for GlobgrpGintstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`globgrp_gintsts::R`](R) reader structure"]
impl crate::Readable for GlobgrpGintstsSpec {}
#[doc = "`reset()` method sets globgrp_gintsts to value 0x1400_0000"]
impl crate::Resettable for GlobgrpGintstsSpec {
    const RESET_VALUE: u32 = 0x1400_0000;
}
