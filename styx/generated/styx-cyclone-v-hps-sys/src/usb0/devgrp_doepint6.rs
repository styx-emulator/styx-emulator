// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepint6` reader"]
pub type R = crate::R<DevgrpDoepint6Spec>;
#[doc = "Register `devgrp_doepint6` writer"]
pub type W = crate::W<DevgrpDoepint6Spec>;
#[doc = "Applies to IN and OUT endpoints.When Scatter/Gather DMA mode is enabled This field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint.\n\nValue on reset: 0"]
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
#[doc = "Field `xfercompl` reader - Applies to IN and OUT endpoints.When Scatter/Gather DMA mode is enabled This field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
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
#[doc = "Field `xfercompl` writer - Applies to IN and OUT endpoints.When Scatter/Gather DMA mode is enabled This field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
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
#[doc = "Applies to control OUT endpoints only. Indicates that the SETUP phase for the control endpoint is complete and no more back-to-back SETUP packets were received for the current control transfer. On this interrupt, the application can decode the received SETUP data packet.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setup {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Setup> for bool {
    #[inline(always)]
    fn from(variant: Setup) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `setup` reader - Applies to control OUT endpoints only. Indicates that the SETUP phase for the control endpoint is complete and no more back-to-back SETUP packets were received for the current control transfer. On this interrupt, the application can decode the received SETUP data packet."]
pub type SetupR = crate::BitReader<Setup>;
impl SetupR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Setup {
        match self.bits {
            false => Setup::Inactive,
            true => Setup::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Setup::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Setup::Active
    }
}
#[doc = "Field `setup` writer - Applies to control OUT endpoints only. Indicates that the SETUP phase for the control endpoint is complete and no more back-to-back SETUP packets were received for the current control transfer. On this interrupt, the application can decode the received SETUP data packet."]
pub type SetupW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies only to control OUT endpoints. Indicates that an OUT token was received when the endpoint was not yet enabled. This interrupt is asserted on the endpoint for which the OUT token was received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outtknepdis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outtknepdis> for bool {
    #[inline(always)]
    fn from(variant: Outtknepdis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outtknepdis` reader - Applies only to control OUT endpoints. Indicates that an OUT token was received when the endpoint was not yet enabled. This interrupt is asserted on the endpoint for which the OUT token was received."]
pub type OuttknepdisR = crate::BitReader<Outtknepdis>;
impl OuttknepdisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outtknepdis {
        match self.bits {
            false => Outtknepdis::Inactive,
            true => Outtknepdis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outtknepdis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outtknepdis::Active
    }
}
#[doc = "Field `outtknepdis` writer - Applies only to control OUT endpoints. Indicates that an OUT token was received when the endpoint was not yet enabled. This interrupt is asserted on the endpoint for which the OUT token was received."]
pub type OuttknepdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This interrupt is valid only for Control OUT endpoints and only in Scatter Gather DMA mode. This interrupt is generated only after the core has transferred all the data that the host has sent during the data phase of a control write transfer, to the system memory buffer. The interrupt indicates to the application that the host has switched from data phase to the status phase of a Control Write transfer. The application can use this interrupt to ACK or STALL the Status phase, after it has decoded the data phase. This is applicable only in Case of Scatter Gather DMA mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stsphsercvd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Stsphsercvd> for bool {
    #[inline(always)]
    fn from(variant: Stsphsercvd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stsphsercvd` reader - This interrupt is valid only for Control OUT endpoints and only in Scatter Gather DMA mode. This interrupt is generated only after the core has transferred all the data that the host has sent during the data phase of a control write transfer, to the system memory buffer. The interrupt indicates to the application that the host has switched from data phase to the status phase of a Control Write transfer. The application can use this interrupt to ACK or STALL the Status phase, after it has decoded the data phase. This is applicable only in Case of Scatter Gather DMA mode."]
pub type StsphsercvdR = crate::BitReader<Stsphsercvd>;
impl StsphsercvdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stsphsercvd {
        match self.bits {
            false => Stsphsercvd::Inactive,
            true => Stsphsercvd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Stsphsercvd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Stsphsercvd::Active
    }
}
#[doc = "Field `stsphsercvd` writer - This interrupt is valid only for Control OUT endpoints and only in Scatter Gather DMA mode. This interrupt is generated only after the core has transferred all the data that the host has sent during the data phase of a control write transfer, to the system memory buffer. The interrupt indicates to the application that the host has switched from data phase to the status phase of a Control Write transfer. The application can use this interrupt to ACK or STALL the Status phase, after it has decoded the data phase. This is applicable only in Case of Scatter Gather DMA mode."]
pub type StsphsercvdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to Control OUT endpoints only. This bit indicates that the core has received more than three back-to-back SETUP packets for this particular endpoint. for information about handling this interrupt,\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Back2backsetup {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Back2backsetup> for bool {
    #[inline(always)]
    fn from(variant: Back2backsetup) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `back2backsetup` reader - Applies to Control OUT endpoints only. This bit indicates that the core has received more than three back-to-back SETUP packets for this particular endpoint. for information about handling this interrupt,"]
pub type Back2backsetupR = crate::BitReader<Back2backsetup>;
impl Back2backsetupR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Back2backsetup {
        match self.bits {
            false => Back2backsetup::Inactive,
            true => Back2backsetup::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Back2backsetup::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Back2backsetup::Active
    }
}
#[doc = "Field `back2backsetup` writer - Applies to Control OUT endpoints only. This bit indicates that the core has received more than three back-to-back SETUP packets for this particular endpoint. for information about handling this interrupt,"]
pub type Back2backsetupW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Applies to OUT endpoints Only This interrupt is asserted when the core detects an overflow or a CRC error for non-Isochronous OUT packet.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outpkterr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outpkterr> for bool {
    #[inline(always)]
    fn from(variant: Outpkterr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outpkterr` reader - Applies to OUT endpoints Only This interrupt is asserted when the core detects an overflow or a CRC error for non-Isochronous OUT packet."]
pub type OutpkterrR = crate::BitReader<Outpkterr>;
impl OutpkterrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outpkterr {
        match self.bits {
            false => Outpkterr::Inactive,
            true => Outpkterr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outpkterr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outpkterr::Active
    }
}
#[doc = "Field `outpkterr` writer - Applies to OUT endpoints Only This interrupt is asserted when the core detects an overflow or a CRC error for non-Isochronous OUT packet."]
pub type OutpkterrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is valid only when Scatter/Gather DMA mode is This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done\n\nValue on reset: 0"]
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
#[doc = "Field `bnaintr` reader - This bit is valid only when Scatter/Gather DMA mode is This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
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
#[doc = "Field `bnaintr` writer - This bit is valid only when Scatter/Gather DMA mode is This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
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
    #[doc = "Bit 0 - Applies to IN and OUT endpoints.When Scatter/Gather DMA mode is enabled This field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
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
    #[doc = "Bit 3 - Applies to control OUT endpoints only. Indicates that the SETUP phase for the control endpoint is complete and no more back-to-back SETUP packets were received for the current control transfer. On this interrupt, the application can decode the received SETUP data packet."]
    #[inline(always)]
    pub fn setup(&self) -> SetupR {
        SetupR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Applies only to control OUT endpoints. Indicates that an OUT token was received when the endpoint was not yet enabled. This interrupt is asserted on the endpoint for which the OUT token was received."]
    #[inline(always)]
    pub fn outtknepdis(&self) -> OuttknepdisR {
        OuttknepdisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This interrupt is valid only for Control OUT endpoints and only in Scatter Gather DMA mode. This interrupt is generated only after the core has transferred all the data that the host has sent during the data phase of a control write transfer, to the system memory buffer. The interrupt indicates to the application that the host has switched from data phase to the status phase of a Control Write transfer. The application can use this interrupt to ACK or STALL the Status phase, after it has decoded the data phase. This is applicable only in Case of Scatter Gather DMA mode."]
    #[inline(always)]
    pub fn stsphsercvd(&self) -> StsphsercvdR {
        StsphsercvdR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Applies to Control OUT endpoints only. This bit indicates that the core has received more than three back-to-back SETUP packets for this particular endpoint. for information about handling this interrupt,"]
    #[inline(always)]
    pub fn back2backsetup(&self) -> Back2backsetupR {
        Back2backsetupR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - Applies to OUT endpoints Only This interrupt is asserted when the core detects an overflow or a CRC error for non-Isochronous OUT packet."]
    #[inline(always)]
    pub fn outpkterr(&self) -> OutpkterrR {
        OutpkterrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is valid only when Scatter/Gather DMA mode is This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
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
    #[doc = "Bit 0 - Applies to IN and OUT endpoints.When Scatter/Gather DMA mode is enabled This field indicates that the requested data from the internal FIFO is moved to external system memory. This interrupt is generated only when the corresponding endpoint descriptor is closed, and the IOC bit for the corresponding descriptor is Set. When Scatter/Gather DMA mode is disabled, this field indicates that the programmed transfer is complete on the AHB as well as on the USB, for this endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn xfercompl(&mut self) -> XfercomplW<DevgrpDoepint6Spec> {
        XfercomplW::new(self, 0)
    }
    #[doc = "Bit 1 - Applies to IN and OUT endpoints. This bit indicates that the endpoint is disabled per the application's request."]
    #[inline(always)]
    #[must_use]
    pub fn epdisbld(&mut self) -> EpdisbldW<DevgrpDoepint6Spec> {
        EpdisbldW::new(self, 1)
    }
    #[doc = "Bit 2 - Applies to IN and OUT endpoints.This is generated only in Internal DMA mode when there is an AHB error during an AHB read/write. The application can read the corresponding endpoint DMA address register to get the error address."]
    #[inline(always)]
    #[must_use]
    pub fn ahberr(&mut self) -> AhberrW<DevgrpDoepint6Spec> {
        AhberrW::new(self, 2)
    }
    #[doc = "Bit 3 - Applies to control OUT endpoints only. Indicates that the SETUP phase for the control endpoint is complete and no more back-to-back SETUP packets were received for the current control transfer. On this interrupt, the application can decode the received SETUP data packet."]
    #[inline(always)]
    #[must_use]
    pub fn setup(&mut self) -> SetupW<DevgrpDoepint6Spec> {
        SetupW::new(self, 3)
    }
    #[doc = "Bit 4 - Applies only to control OUT endpoints. Indicates that an OUT token was received when the endpoint was not yet enabled. This interrupt is asserted on the endpoint for which the OUT token was received."]
    #[inline(always)]
    #[must_use]
    pub fn outtknepdis(&mut self) -> OuttknepdisW<DevgrpDoepint6Spec> {
        OuttknepdisW::new(self, 4)
    }
    #[doc = "Bit 5 - This interrupt is valid only for Control OUT endpoints and only in Scatter Gather DMA mode. This interrupt is generated only after the core has transferred all the data that the host has sent during the data phase of a control write transfer, to the system memory buffer. The interrupt indicates to the application that the host has switched from data phase to the status phase of a Control Write transfer. The application can use this interrupt to ACK or STALL the Status phase, after it has decoded the data phase. This is applicable only in Case of Scatter Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn stsphsercvd(&mut self) -> StsphsercvdW<DevgrpDoepint6Spec> {
        StsphsercvdW::new(self, 5)
    }
    #[doc = "Bit 6 - Applies to Control OUT endpoints only. This bit indicates that the core has received more than three back-to-back SETUP packets for this particular endpoint. for information about handling this interrupt,"]
    #[inline(always)]
    #[must_use]
    pub fn back2backsetup(&mut self) -> Back2backsetupW<DevgrpDoepint6Spec> {
        Back2backsetupW::new(self, 6)
    }
    #[doc = "Bit 8 - Applies to OUT endpoints Only This interrupt is asserted when the core detects an overflow or a CRC error for non-Isochronous OUT packet."]
    #[inline(always)]
    #[must_use]
    pub fn outpkterr(&mut self) -> OutpkterrW<DevgrpDoepint6Spec> {
        OutpkterrW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is valid only when Scatter/Gather DMA mode is This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process, such as Host busy or DMA done"]
    #[inline(always)]
    #[must_use]
    pub fn bnaintr(&mut self) -> BnaintrW<DevgrpDoepint6Spec> {
        BnaintrW::new(self, 9)
    }
    #[doc = "Bit 11 - This bit indicates to the application that an ISOC OUT packet has been dropped. This bit does not have an associated mask bit and does not generate an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn pktdrpsts(&mut self) -> PktdrpstsW<DevgrpDoepint6Spec> {
        PktdrpstsW::new(self, 11)
    }
    #[doc = "Bit 12 - The core generates this interrupt when babble is received for the endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn bbleerr(&mut self) -> BbleerrW<DevgrpDoepint6Spec> {
        BbleerrW::new(self, 12)
    }
    #[doc = "Bit 13 - The core generates this interrupt when a NAK is transmitted or received by the device. In case of isochronous IN endpoints the interrupt gets generated when a zero length packet is transmitted due to un-availability of data in the TXFifo."]
    #[inline(always)]
    #[must_use]
    pub fn nakintrpt(&mut self) -> NakintrptW<DevgrpDoepint6Spec> {
        NakintrptW::new(self, 13)
    }
    #[doc = "Bit 14 - The core generates this interrupt when a NYET response is transmitted for a non isochronous OUT endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn nyetintrpt(&mut self) -> NyetintrptW<DevgrpDoepint6Spec> {
        NyetintrptW::new(self, 14)
    }
}
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint6::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepint6Spec;
impl crate::RegisterSpec for DevgrpDoepint6Spec {
    type Ux = u32;
    const OFFSET: u64 = 3016u64;
}
#[doc = "`read()` method returns [`devgrp_doepint6::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepint6Spec {}
#[doc = "`reset()` method sets devgrp_doepint6 to value 0"]
impl crate::Resettable for DevgrpDoepint6Spec {
    const RESET_VALUE: u32 = 0;
}
