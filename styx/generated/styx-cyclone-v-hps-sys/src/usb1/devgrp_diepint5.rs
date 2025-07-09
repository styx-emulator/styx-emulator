// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepint5` reader"]
pub type R = crate::R<DevgrpDiepint5Spec>;
#[doc = "Register `devgrp_diepint5` writer"]
pub type W = crate::W<DevgrpDiepint5Spec>;
#[doc = "Applies to IN and OUT endpoints. When Scatter/Gather DMA mode is enabled - for IN endpoint this field indicates that the requested data from the descriptor is moved from external system memory to internal FIFO. - for OUT endpoint this field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xfercompl {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Xfercompl> for bool {
    #[inline(always)]
    fn from(variant: Xfercompl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xfercompl` reader - Applies to IN and OUT endpoints. When Scatter/Gather DMA mode is enabled - for IN endpoint this field indicates that the requested data from the descriptor is moved from external system memory to internal FIFO. - for OUT endpoint this field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
pub type XfercomplR = crate::BitReader<Xfercompl>;
impl XfercomplR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xfercompl {
        match self.bits {
            false => Xfercompl::Inactive,
            true => Xfercompl::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Xfercompl::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Xfercompl::Active
    }
}
#[doc = "Field `xfercompl` writer - Applies to IN and OUT endpoints. When Scatter/Gather DMA mode is enabled - for IN endpoint this field indicates that the requested data from the descriptor is moved from external system memory to internal FIFO. - for OUT endpoint this field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
pub type XfercomplW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to IN and OUT endpoints. This bit indicates that the endpoint is disabled per the application's request.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epdisbld {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Epdisbld> for bool {
    #[inline(always)]
    fn from(variant: Epdisbld) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epdisbld` reader - Applies to IN and OUT endpoints. This bit indicates that the endpoint is disabled per the application's request."]
pub type EpdisbldR = crate::BitReader<Epdisbld>;
impl EpdisbldR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epdisbld {
        match self.bits {
            false => Epdisbld::Inactive,
            true => Epdisbld::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Epdisbld::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Epdisbld::Active
    }
}
#[doc = "Field `epdisbld` writer - Applies to IN and OUT endpoints. This bit indicates that the endpoint is disabled per the application's request."]
pub type EpdisbldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to IN and OUT endpoints.This is generated only in Internal DMA mode when there is an AHB error during an AHB read/write. The application can read the corresponding endpoint DMA address register to get the error address.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ahberr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ahberr> for bool {
    #[inline(always)]
    fn from(variant: Ahberr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ahberr` reader - Applies to IN and OUT endpoints.This is generated only in Internal DMA mode when there is an AHB error during an AHB read/write. The application can read the corresponding endpoint DMA address register to get the error address."]
pub type AhberrR = crate::BitReader<Ahberr>;
impl AhberrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ahberr {
        match self.bits {
            false => Ahberr::Inactive,
            true => Ahberr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ahberr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ahberr::Active
    }
}
#[doc = "Field `ahberr` writer - Applies to IN and OUT endpoints.This is generated only in Internal DMA mode when there is an AHB error during an AHB read/write. The application can read the corresponding endpoint DMA address register to get the error address."]
pub type AhberrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In shared TX FIFO mode, applies to non-isochronous IN endpoints only. In dedicated FIFO mode, applies only to Control IN endpoints. In Scatter/Gather DMA mode, the TimeOUT interrupt is notasserted. Indicates that the core has detected a timeout condition on the USB for the last IN token on this endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timeout {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Timeout> for bool {
    #[inline(always)]
    fn from(variant: Timeout) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timeout` reader - In shared TX FIFO mode, applies to non-isochronous IN endpoints only. In dedicated FIFO mode, applies only to Control IN endpoints. In Scatter/Gather DMA mode, the TimeOUT interrupt is notasserted. Indicates that the core has detected a timeout condition on the USB for the last IN token on this endpoint."]
pub type TimeoutR = crate::BitReader<Timeout>;
impl TimeoutR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timeout {
        match self.bits {
            false => Timeout::Inactive,
            true => Timeout::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Timeout::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Timeout::Active
    }
}
#[doc = "Field `timeout` writer - In shared TX FIFO mode, applies to non-isochronous IN endpoints only. In dedicated FIFO mode, applies only to Control IN endpoints. In Scatter/Gather DMA mode, the TimeOUT interrupt is notasserted. Indicates that the core has detected a timeout condition on the USB for the last IN token on this endpoint."]
pub type TimeoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to non-periodic IN endpoints only. Indicates that an IN token was received when the associated TxFIFO (periodic/non-periodic) was empty. This interrupt is asserted on the endpoint for which the IN token was received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intkntxfemp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Intkntxfemp> for bool {
    #[inline(always)]
    fn from(variant: Intkntxfemp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `intkntxfemp` reader - Applies to non-periodic IN endpoints only. Indicates that an IN token was received when the associated TxFIFO (periodic/non-periodic) was empty. This interrupt is asserted on the endpoint for which the IN token was received."]
pub type IntkntxfempR = crate::BitReader<Intkntxfemp>;
impl IntkntxfempR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Intkntxfemp {
        match self.bits {
            false => Intkntxfemp::Inactive,
            true => Intkntxfemp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Intkntxfemp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Intkntxfemp::Active
    }
}
#[doc = "Field `intkntxfemp` writer - Applies to non-periodic IN endpoints only. Indicates that an IN token was received when the associated TxFIFO (periodic/non-periodic) was empty. This interrupt is asserted on the endpoint for which the IN token was received."]
pub type IntkntxfempW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to non-periodic IN endpoints only. Indicates that the data in the top of the non-periodic TxFIFO belongs to an endpoint other than the one for which the IN token was received. This interrupt is asserted on the endpoint for which the IN token was received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intknepmis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Intknepmis> for bool {
    #[inline(always)]
    fn from(variant: Intknepmis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `intknepmis` reader - Applies to non-periodic IN endpoints only. Indicates that the data in the top of the non-periodic TxFIFO belongs to an endpoint other than the one for which the IN token was received. This interrupt is asserted on the endpoint for which the IN token was received."]
pub type IntknepmisR = crate::BitReader<Intknepmis>;
impl IntknepmisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Intknepmis {
        match self.bits {
            false => Intknepmis::Inactive,
            true => Intknepmis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Intknepmis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Intknepmis::Active
    }
}
#[doc = "Field `intknepmis` writer - Applies to non-periodic IN endpoints only. Indicates that the data in the top of the non-periodic TxFIFO belongs to an endpoint other than the one for which the IN token was received. This interrupt is asserted on the endpoint for which the IN token was received."]
pub type IntknepmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to periodic IN endpoints only. This bit can be cleared when the application clears the IN endpoint NAK by writing to DIEPCTLn.CNAK. This interrupt indicates that the core has sampled the NAK bit Set (either by the application or by the core). The interrupt indicates that the IN endpoint NAK bit Set by the application has taken effect in the core.This interrupt does not guarantee that a NAK handshake is sent on the USB. A STALL bit takes priority over a NAK bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepnakeff {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepnakeff> for bool {
    #[inline(always)]
    fn from(variant: Inepnakeff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepnakeff` reader - Applies to periodic IN endpoints only. This bit can be cleared when the application clears the IN endpoint NAK by writing to DIEPCTLn.CNAK. This interrupt indicates that the core has sampled the NAK bit Set (either by the application or by the core). The interrupt indicates that the IN endpoint NAK bit Set by the application has taken effect in the core.This interrupt does not guarantee that a NAK handshake is sent on the USB. A STALL bit takes priority over a NAK bit."]
pub type InepnakeffR = crate::BitReader<Inepnakeff>;
impl InepnakeffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepnakeff {
        match self.bits {
            false => Inepnakeff::Inactive,
            true => Inepnakeff::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepnakeff::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepnakeff::Active
    }
}
#[doc = "Field `inepnakeff` writer - Applies to periodic IN endpoints only. This bit can be cleared when the application clears the IN endpoint NAK by writing to DIEPCTLn.CNAK. This interrupt indicates that the core has sampled the NAK bit Set (either by the application or by the core). The interrupt indicates that the IN endpoint NAK bit Set by the application has taken effect in the core.This interrupt does not guarantee that a NAK handshake is sent on the USB. A STALL bit takes priority over a NAK bit."]
pub type InepnakeffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is valid only for IN Endpoints This interrupt is asserted when the TxFIFO for this endpoint is either half or completely empty. The half or completely empty status is determined by the TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.NPTxFEmpLvl)).\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfemp {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txfemp> for bool {
    #[inline(always)]
    fn from(variant: Txfemp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfemp` reader - This bit is valid only for IN Endpoints This interrupt is asserted when the TxFIFO for this endpoint is either half or completely empty. The half or completely empty status is determined by the TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.NPTxFEmpLvl))."]
pub type TxfempR = crate::BitReader<Txfemp>;
impl TxfempR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfemp {
        match self.bits {
            false => Txfemp::Inactive,
            true => Txfemp::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txfemp::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txfemp::Active
    }
}
#[doc = "Field `txfemp` writer - This bit is valid only for IN Endpoints This interrupt is asserted when the TxFIFO for this endpoint is either half or completely empty. The half or completely empty status is determined by the TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.NPTxFEmpLvl))."]
pub type TxfempW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to IN endpoints Only. The core generates this interrupt when it detects a transmit FIFO underrun condition for this endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfifoundrn {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txfifoundrn> for bool {
    #[inline(always)]
    fn from(variant: Txfifoundrn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfifoundrn` reader - Applies to IN endpoints Only. The core generates this interrupt when it detects a transmit FIFO underrun condition for this endpoint."]
pub type TxfifoundrnR = crate::BitReader<Txfifoundrn>;
impl TxfifoundrnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfifoundrn {
        match self.bits {
            false => Txfifoundrn::Inactive,
            true => Txfifoundrn::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txfifoundrn::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txfifoundrn::Active
    }
}
#[doc = "Field `txfifoundrn` writer - Applies to IN endpoints Only. The core generates this interrupt when it detects a transmit FIFO underrun condition for this endpoint."]
pub type TxfifoundrnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bnaintr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Bnaintr> for bool {
    #[inline(always)]
    fn from(variant: Bnaintr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bnaintr` reader - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
pub type BnaintrR = crate::BitReader<Bnaintr>;
impl BnaintrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bnaintr {
        match self.bits {
            false => Bnaintr::Inactive,
            true => Bnaintr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Bnaintr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Bnaintr::Active
    }
}
#[doc = "Field `bnaintr` writer - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
pub type BnaintrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit indicates to the application that an ISOC OUT packet has been dropped. This bit does not have an associated mask bit and does not generate an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pktdrpsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Pktdrpsts> for bool {
    #[inline(always)]
    fn from(variant: Pktdrpsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pktdrpsts` reader - This bit indicates to the application that an ISOC OUT packet has been dropped. This bit does not have an associated mask bit and does not generate an interrupt."]
pub type PktdrpstsR = crate::BitReader<Pktdrpsts>;
impl PktdrpstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pktdrpsts {
        match self.bits {
            false => Pktdrpsts::Inactive,
            true => Pktdrpsts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Pktdrpsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Pktdrpsts::Active
    }
}
#[doc = "Field `pktdrpsts` writer - This bit indicates to the application that an ISOC OUT packet has been dropped. This bit does not have an associated mask bit and does not generate an interrupt."]
pub type PktdrpstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core generates this interrupt when babble is received for the endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bbleerr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Bbleerr> for bool {
    #[inline(always)]
    fn from(variant: Bbleerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bbleerr` reader - The core generates this interrupt when babble is received for the endpoint."]
pub type BbleerrR = crate::BitReader<Bbleerr>;
impl BbleerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bbleerr {
        match self.bits {
            false => Bbleerr::Inactive,
            true => Bbleerr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Bbleerr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Bbleerr::Active
    }
}
#[doc = "Field `bbleerr` writer - The core generates this interrupt when babble is received for the endpoint."]
pub type BbleerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core generates this interrupt when a NAK is transmitted or received by the device. In case of isochronous IN endpoints the interrupt gets generated when a zero length packet is transmitted due to un-availability of data in the TXFifo.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nakintrpt {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Nakintrpt> for bool {
    #[inline(always)]
    fn from(variant: Nakintrpt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nakintrpt` reader - The core generates this interrupt when a NAK is transmitted or received by the device. In case of isochronous IN endpoints the interrupt gets generated when a zero length packet is transmitted due to un-availability of data in the TXFifo."]
pub type NakintrptR = crate::BitReader<Nakintrpt>;
impl NakintrptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nakintrpt {
        match self.bits {
            false => Nakintrpt::Inactive,
            true => Nakintrpt::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Nakintrpt::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Nakintrpt::Active
    }
}
#[doc = "Field `nakintrpt` writer - The core generates this interrupt when a NAK is transmitted or received by the device. In case of isochronous IN endpoints the interrupt gets generated when a zero length packet is transmitted due to un-availability of data in the TXFifo."]
pub type NakintrptW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core generates this interrupt when a NYET response is transmitted for a non isochronous OUT endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nyetintrpt {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Nyetintrpt> for bool {
    #[inline(always)]
    fn from(variant: Nyetintrpt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nyetintrpt` reader - The core generates this interrupt when a NYET response is transmitted for a non isochronous OUT endpoint."]
pub type NyetintrptR = crate::BitReader<Nyetintrpt>;
impl NyetintrptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nyetintrpt {
        match self.bits {
            false => Nyetintrpt::Inactive,
            true => Nyetintrpt::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Nyetintrpt::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Nyetintrpt::Active
    }
}
#[doc = "Field `nyetintrpt` writer - The core generates this interrupt when a NYET response is transmitted for a non isochronous OUT endpoint."]
pub type NyetintrptW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Applies to IN and OUT endpoints. When Scatter/Gather DMA mode is enabled - for IN endpoint this field indicates that the requested data from the descriptor is moved from external system memory to internal FIFO. - for OUT endpoint this field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
    #[inline(always)]
    pub fn xfercompl(&self) -> XfercomplR {
        XfercomplR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Applies to IN and OUT endpoints. This bit indicates that the endpoint is disabled per the application's request."]
    #[inline(always)]
    pub fn epdisbld(&self) -> EpdisbldR {
        EpdisbldR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Applies to IN and OUT endpoints.This is generated only in Internal DMA mode when there is an AHB error during an AHB read/write. The application can read the corresponding endpoint DMA address register to get the error address."]
    #[inline(always)]
    pub fn ahberr(&self) -> AhberrR {
        AhberrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - In shared TX FIFO mode, applies to non-isochronous IN endpoints only. In dedicated FIFO mode, applies only to Control IN endpoints. In Scatter/Gather DMA mode, the TimeOUT interrupt is notasserted. Indicates that the core has detected a timeout condition on the USB for the last IN token on this endpoint."]
    #[inline(always)]
    pub fn timeout(&self) -> TimeoutR {
        TimeoutR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Applies to non-periodic IN endpoints only. Indicates that an IN token was received when the associated TxFIFO (periodic/non-periodic) was empty. This interrupt is asserted on the endpoint for which the IN token was received."]
    #[inline(always)]
    pub fn intkntxfemp(&self) -> IntkntxfempR {
        IntkntxfempR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Applies to non-periodic IN endpoints only. Indicates that the data in the top of the non-periodic TxFIFO belongs to an endpoint other than the one for which the IN token was received. This interrupt is asserted on the endpoint for which the IN token was received."]
    #[inline(always)]
    pub fn intknepmis(&self) -> IntknepmisR {
        IntknepmisR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Applies to periodic IN endpoints only. This bit can be cleared when the application clears the IN endpoint NAK by writing to DIEPCTLn.CNAK. This interrupt indicates that the core has sampled the NAK bit Set (either by the application or by the core). The interrupt indicates that the IN endpoint NAK bit Set by the application has taken effect in the core.This interrupt does not guarantee that a NAK handshake is sent on the USB. A STALL bit takes priority over a NAK bit."]
    #[inline(always)]
    pub fn inepnakeff(&self) -> InepnakeffR {
        InepnakeffR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is valid only for IN Endpoints This interrupt is asserted when the TxFIFO for this endpoint is either half or completely empty. The half or completely empty status is determined by the TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.NPTxFEmpLvl))."]
    #[inline(always)]
    pub fn txfemp(&self) -> TxfempR {
        TxfempR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Applies to IN endpoints Only. The core generates this interrupt when it detects a transmit FIFO underrun condition for this endpoint."]
    #[inline(always)]
    pub fn txfifoundrn(&self) -> TxfifoundrnR {
        TxfifoundrnR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
    #[inline(always)]
    pub fn bnaintr(&self) -> BnaintrR {
        BnaintrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit indicates to the application that an ISOC OUT packet has been dropped. This bit does not have an associated mask bit and does not generate an interrupt."]
    #[inline(always)]
    pub fn pktdrpsts(&self) -> PktdrpstsR {
        PktdrpstsR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - The core generates this interrupt when babble is received for the endpoint."]
    #[inline(always)]
    pub fn bbleerr(&self) -> BbleerrR {
        BbleerrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - The core generates this interrupt when a NAK is transmitted or received by the device. In case of isochronous IN endpoints the interrupt gets generated when a zero length packet is transmitted due to un-availability of data in the TXFifo."]
    #[inline(always)]
    pub fn nakintrpt(&self) -> NakintrptR {
        NakintrptR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - The core generates this interrupt when a NYET response is transmitted for a non isochronous OUT endpoint."]
    #[inline(always)]
    pub fn nyetintrpt(&self) -> NyetintrptR {
        NyetintrptR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Applies to IN and OUT endpoints. When Scatter/Gather DMA mode is enabled - for IN endpoint this field indicates that the requested data from the descriptor is moved from external system memory to internal FIFO. - for OUT endpoint this field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn xfercompl(&mut self) -> XfercomplW<DevgrpDiepint5Spec> {
        XfercomplW::new(self, 0)
    }
    #[doc = "Bit 1 - Applies to IN and OUT endpoints. This bit indicates that the endpoint is disabled per the application's request."]
    #[inline(always)]
    #[must_use]
    pub fn epdisbld(&mut self) -> EpdisbldW<DevgrpDiepint5Spec> {
        EpdisbldW::new(self, 1)
    }
    #[doc = "Bit 2 - Applies to IN and OUT endpoints.This is generated only in Internal DMA mode when there is an AHB error during an AHB read/write. The application can read the corresponding endpoint DMA address register to get the error address."]
    #[inline(always)]
    #[must_use]
    pub fn ahberr(&mut self) -> AhberrW<DevgrpDiepint5Spec> {
        AhberrW::new(self, 2)
    }
    #[doc = "Bit 3 - In shared TX FIFO mode, applies to non-isochronous IN endpoints only. In dedicated FIFO mode, applies only to Control IN endpoints. In Scatter/Gather DMA mode, the TimeOUT interrupt is notasserted. Indicates that the core has detected a timeout condition on the USB for the last IN token on this endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn timeout(&mut self) -> TimeoutW<DevgrpDiepint5Spec> {
        TimeoutW::new(self, 3)
    }
    #[doc = "Bit 4 - Applies to non-periodic IN endpoints only. Indicates that an IN token was received when the associated TxFIFO (periodic/non-periodic) was empty. This interrupt is asserted on the endpoint for which the IN token was received."]
    #[inline(always)]
    #[must_use]
    pub fn intkntxfemp(&mut self) -> IntkntxfempW<DevgrpDiepint5Spec> {
        IntkntxfempW::new(self, 4)
    }
    #[doc = "Bit 5 - Applies to non-periodic IN endpoints only. Indicates that the data in the top of the non-periodic TxFIFO belongs to an endpoint other than the one for which the IN token was received. This interrupt is asserted on the endpoint for which the IN token was received."]
    #[inline(always)]
    #[must_use]
    pub fn intknepmis(&mut self) -> IntknepmisW<DevgrpDiepint5Spec> {
        IntknepmisW::new(self, 5)
    }
    #[doc = "Bit 6 - Applies to periodic IN endpoints only. This bit can be cleared when the application clears the IN endpoint NAK by writing to DIEPCTLn.CNAK. This interrupt indicates that the core has sampled the NAK bit Set (either by the application or by the core). The interrupt indicates that the IN endpoint NAK bit Set by the application has taken effect in the core.This interrupt does not guarantee that a NAK handshake is sent on the USB. A STALL bit takes priority over a NAK bit."]
    #[inline(always)]
    #[must_use]
    pub fn inepnakeff(&mut self) -> InepnakeffW<DevgrpDiepint5Spec> {
        InepnakeffW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is valid only for IN Endpoints This interrupt is asserted when the TxFIFO for this endpoint is either half or completely empty. The half or completely empty status is determined by the TxFIFO Empty Level bit in the Core AHB Configuration register (GAHBCFG.NPTxFEmpLvl))."]
    #[inline(always)]
    #[must_use]
    pub fn txfemp(&mut self) -> TxfempW<DevgrpDiepint5Spec> {
        TxfempW::new(self, 7)
    }
    #[doc = "Bit 8 - Applies to IN endpoints Only. The core generates this interrupt when it detects a transmit FIFO underrun condition for this endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn txfifoundrn(&mut self) -> TxfifoundrnW<DevgrpDiepint5Spec> {
        TxfifoundrnW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
    #[inline(always)]
    #[must_use]
    pub fn bnaintr(&mut self) -> BnaintrW<DevgrpDiepint5Spec> {
        BnaintrW::new(self, 9)
    }
    #[doc = "Bit 11 - This bit indicates to the application that an ISOC OUT packet has been dropped. This bit does not have an associated mask bit and does not generate an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn pktdrpsts(&mut self) -> PktdrpstsW<DevgrpDiepint5Spec> {
        PktdrpstsW::new(self, 11)
    }
    #[doc = "Bit 12 - The core generates this interrupt when babble is received for the endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn bbleerr(&mut self) -> BbleerrW<DevgrpDiepint5Spec> {
        BbleerrW::new(self, 12)
    }
    #[doc = "Bit 13 - The core generates this interrupt when a NAK is transmitted or received by the device. In case of isochronous IN endpoints the interrupt gets generated when a zero length packet is transmitted due to un-availability of data in the TXFifo."]
    #[inline(always)]
    #[must_use]
    pub fn nakintrpt(&mut self) -> NakintrptW<DevgrpDiepint5Spec> {
        NakintrptW::new(self, 13)
    }
    #[doc = "Bit 14 - The core generates this interrupt when a NYET response is transmitted for a non isochronous OUT endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn nyetintrpt(&mut self) -> NyetintrptW<DevgrpDiepint5Spec> {
        NyetintrptW::new(self, 14)
    }
}
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint5::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepint5Spec;
impl crate::RegisterSpec for DevgrpDiepint5Spec {
    type Ux = u32;
    const OFFSET: u64 = 2472u64;
}
#[doc = "`read()` method returns [`devgrp_diepint5::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepint5Spec {}
#[doc = "`reset()` method sets devgrp_diepint5 to value 0x80"]
impl crate::Resettable for DevgrpDiepint5Spec {
    const RESET_VALUE: u32 = 0x80;
}
