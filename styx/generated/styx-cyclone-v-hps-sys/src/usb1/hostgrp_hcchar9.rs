// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `hostgrp_hcchar9` reader"]
pub type R = crate::R<HostgrpHcchar9Spec>;
#[doc = "Register `hostgrp_hcchar9` writer"]
pub type W = crate::W<HostgrpHcchar9Spec>;
#[doc = "Field `mps` reader - Indicates the maximum packet size of the associated endpoint."]
pub type MpsR = crate::FieldReader<u16>;
#[doc = "Field `mps` writer - Indicates the maximum packet size of the associated endpoint."]
pub type MpsW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Indicates the endpoint number on the device serving as the data source or sink.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Epnum {
    #[doc = "0: `0`"]
    Endpt0 = 0,
    #[doc = "1: `1`"]
    Endpt1 = 1,
    #[doc = "2: `10`"]
    Endpt2 = 2,
    #[doc = "3: `11`"]
    Endpt3 = 3,
    #[doc = "4: `100`"]
    Endpt4 = 4,
    #[doc = "5: `101`"]
    Endpt5 = 5,
    #[doc = "6: `110`"]
    Endpt6 = 6,
    #[doc = "7: `111`"]
    Endpt7 = 7,
    #[doc = "8: `1000`"]
    Endpt8 = 8,
    #[doc = "9: `1001`"]
    Endpt9 = 9,
    #[doc = "10: `1010`"]
    Endpt10 = 10,
    #[doc = "11: `1011`"]
    Endpt11 = 11,
    #[doc = "12: `1100`"]
    Endpt12 = 12,
    #[doc = "13: `1101`"]
    Endpt13 = 13,
    #[doc = "14: `1110`"]
    Endpt14 = 14,
    #[doc = "15: `1111`"]
    Endpt15 = 15,
}
impl From<Epnum> for u8 {
    #[inline(always)]
    fn from(variant: Epnum) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Epnum {
    type Ux = u8;
}
#[doc = "Field `epnum` reader - Indicates the endpoint number on the device serving as the data source or sink."]
pub type EpnumR = crate::FieldReader<Epnum>;
impl EpnumR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epnum {
        match self.bits {
            0 => Epnum::Endpt0,
            1 => Epnum::Endpt1,
            2 => Epnum::Endpt2,
            3 => Epnum::Endpt3,
            4 => Epnum::Endpt4,
            5 => Epnum::Endpt5,
            6 => Epnum::Endpt6,
            7 => Epnum::Endpt7,
            8 => Epnum::Endpt8,
            9 => Epnum::Endpt9,
            10 => Epnum::Endpt10,
            11 => Epnum::Endpt11,
            12 => Epnum::Endpt12,
            13 => Epnum::Endpt13,
            14 => Epnum::Endpt14,
            15 => Epnum::Endpt15,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_endpt0(&self) -> bool {
        *self == Epnum::Endpt0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_endpt1(&self) -> bool {
        *self == Epnum::Endpt1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_endpt2(&self) -> bool {
        *self == Epnum::Endpt2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_endpt3(&self) -> bool {
        *self == Epnum::Endpt3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_endpt4(&self) -> bool {
        *self == Epnum::Endpt4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_endpt5(&self) -> bool {
        *self == Epnum::Endpt5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_endpt6(&self) -> bool {
        *self == Epnum::Endpt6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_endpt7(&self) -> bool {
        *self == Epnum::Endpt7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_endpt8(&self) -> bool {
        *self == Epnum::Endpt8
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_endpt9(&self) -> bool {
        *self == Epnum::Endpt9
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_endpt10(&self) -> bool {
        *self == Epnum::Endpt10
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_endpt11(&self) -> bool {
        *self == Epnum::Endpt11
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_endpt12(&self) -> bool {
        *self == Epnum::Endpt12
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_endpt13(&self) -> bool {
        *self == Epnum::Endpt13
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_endpt14(&self) -> bool {
        *self == Epnum::Endpt14
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_endpt15(&self) -> bool {
        *self == Epnum::Endpt15
    }
}
#[doc = "Field `epnum` writer - Indicates the endpoint number on the device serving as the data source or sink."]
pub type EpnumW<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Epnum>;
impl<'a, REG> EpnumW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn endpt0(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn endpt1(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt1)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn endpt2(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt2)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn endpt3(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt3)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn endpt4(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt4)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn endpt5(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt5)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn endpt6(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt6)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn endpt7(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt7)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn endpt8(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt8)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn endpt9(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt9)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn endpt10(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt10)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn endpt11(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt11)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn endpt12(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt12)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn endpt13(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt13)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn endpt14(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt14)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn endpt15(self) -> &'a mut crate::W<REG> {
        self.variant(Epnum::Endpt15)
    }
}
#[doc = "Indicates whether the transaction is IN or OUT.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epdir {
    #[doc = "0: `0`"]
    Out = 0,
    #[doc = "1: `1`"]
    In = 1,
}
impl From<Epdir> for bool {
    #[inline(always)]
    fn from(variant: Epdir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `epdir` reader - Indicates whether the transaction is IN or OUT."]
pub type EpdirR = crate::BitReader<Epdir>;
impl EpdirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epdir {
        match self.bits {
            false => Epdir::Out,
            true => Epdir::In,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_out(&self) -> bool {
        *self == Epdir::Out
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_in(&self) -> bool {
        *self == Epdir::In
    }
}
#[doc = "Field `epdir` writer - Indicates whether the transaction is IN or OUT."]
pub type EpdirW<'a, REG> = crate::BitWriter<'a, REG, Epdir>;
impl<'a, REG> EpdirW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn out(self) -> &'a mut crate::W<REG> {
        self.variant(Epdir::Out)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn in_(self) -> &'a mut crate::W<REG> {
        self.variant(Epdir::In)
    }
}
#[doc = "This field is set by the application to indicate that this channel is communicating to a low-speed device. The application must program this bit when a low speed device is connected to the host through an FS HUB. The HS OTG Host core uses this field to drive the XCVR_SELECT signal to 0x3 while communicating to the LS Device through the FS hub. In a peer to peer setup, the HS OTG Host core ignores this bit even if it is set by the application software\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lspddev {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lspddev> for bool {
    #[inline(always)]
    fn from(variant: Lspddev) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lspddev` reader - This field is set by the application to indicate that this channel is communicating to a low-speed device. The application must program this bit when a low speed device is connected to the host through an FS HUB. The HS OTG Host core uses this field to drive the XCVR_SELECT signal to 0x3 while communicating to the LS Device through the FS hub. In a peer to peer setup, the HS OTG Host core ignores this bit even if it is set by the application software"]
pub type LspddevR = crate::BitReader<Lspddev>;
impl LspddevR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lspddev {
        match self.bits {
            false => Lspddev::Disabled,
            true => Lspddev::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lspddev::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lspddev::Enabled
    }
}
#[doc = "Field `lspddev` writer - This field is set by the application to indicate that this channel is communicating to a low-speed device. The application must program this bit when a low speed device is connected to the host through an FS HUB. The HS OTG Host core uses this field to drive the XCVR_SELECT signal to 0x3 while communicating to the LS Device through the FS hub. In a peer to peer setup, the HS OTG Host core ignores this bit even if it is set by the application software"]
pub type LspddevW<'a, REG> = crate::BitWriter<'a, REG, Lspddev>;
impl<'a, REG> LspddevW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lspddev::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lspddev::Enabled)
    }
}
#[doc = "Indicates the transfer type selected.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Eptype {
    #[doc = "0: `0`"]
    Ctrl = 0,
    #[doc = "1: `1`"]
    Isoc = 1,
    #[doc = "2: `10`"]
    Bulk = 2,
    #[doc = "3: `11`"]
    Interr = 3,
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
#[doc = "Field `eptype` reader - Indicates the transfer type selected."]
pub type EptypeR = crate::FieldReader<Eptype>;
impl EptypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eptype {
        match self.bits {
            0 => Eptype::Ctrl,
            1 => Eptype::Isoc,
            2 => Eptype::Bulk,
            3 => Eptype::Interr,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ctrl(&self) -> bool {
        *self == Eptype::Ctrl
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_isoc(&self) -> bool {
        *self == Eptype::Isoc
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_bulk(&self) -> bool {
        *self == Eptype::Bulk
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Eptype::Interr
    }
}
#[doc = "Field `eptype` writer - Indicates the transfer type selected."]
pub type EptypeW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Eptype>;
impl<'a, REG> EptypeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ctrl(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Ctrl)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn isoc(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Isoc)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn bulk(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Bulk)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn interr(self) -> &'a mut crate::W<REG> {
        self.variant(Eptype::Interr)
    }
}
#[doc = "When the Split Enable bit of the Host Channel-n Split Control register (HCSPLTn.SpltEna) is reset (0), this field indicates to the host the number of transactions that must be executed per microframe for this periodic endpoint. for non periodic transfers, this field is used only in DMA mode, and specifies the number packets to be fetched for this channel before the internal DMA engine changes arbitration. When HCSPLTn.SpltEna is Set (1), this field indicates the number of immediate retries to be performed for a periodic split transactions on transaction errors. This field must be set to at least 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ec {
    #[doc = "1: `1`"]
    Transone = 1,
    #[doc = "2: `10`"]
    Transtwo = 2,
    #[doc = "3: `11`"]
    Transthree = 3,
}
impl From<Ec> for u8 {
    #[inline(always)]
    fn from(variant: Ec) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ec {
    type Ux = u8;
}
#[doc = "Field `ec` reader - When the Split Enable bit of the Host Channel-n Split Control register (HCSPLTn.SpltEna) is reset (0), this field indicates to the host the number of transactions that must be executed per microframe for this periodic endpoint. for non periodic transfers, this field is used only in DMA mode, and specifies the number packets to be fetched for this channel before the internal DMA engine changes arbitration. When HCSPLTn.SpltEna is Set (1), this field indicates the number of immediate retries to be performed for a periodic split transactions on transaction errors. This field must be set to at least 1."]
pub type EcR = crate::FieldReader<Ec>;
impl EcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ec {
        match self.bits {
            1 => Ec::Transone,
            2 => Ec::Transtwo,
            3 => Ec::Transthree,
            _ => unreachable!(),
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_transone(&self) -> bool {
        *self == Ec::Transone
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_transtwo(&self) -> bool {
        *self == Ec::Transtwo
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_transthree(&self) -> bool {
        *self == Ec::Transthree
    }
}
#[doc = "Field `ec` writer - When the Split Enable bit of the Host Channel-n Split Control register (HCSPLTn.SpltEna) is reset (0), this field indicates to the host the number of transactions that must be executed per microframe for this periodic endpoint. for non periodic transfers, this field is used only in DMA mode, and specifies the number packets to be fetched for this channel before the internal DMA engine changes arbitration. When HCSPLTn.SpltEna is Set (1), this field indicates the number of immediate retries to be performed for a periodic split transactions on transaction errors. This field must be set to at least 1."]
pub type EcW<'a, REG> = crate::FieldWriter<'a, REG, 2, Ec>;
impl<'a, REG> EcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn transone(self) -> &'a mut crate::W<REG> {
        self.variant(Ec::Transone)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn transtwo(self) -> &'a mut crate::W<REG> {
        self.variant(Ec::Transtwo)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn transthree(self) -> &'a mut crate::W<REG> {
        self.variant(Ec::Transthree)
    }
}
#[doc = "Field `devaddr` reader - This field selects the specific device serving as the data source or sink."]
pub type DevaddrR = crate::FieldReader;
#[doc = "Field `devaddr` writer - This field selects the specific device serving as the data source or sink."]
pub type DevaddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "The application sets this bit to stop transmitting/receiving data on a channel, even before the transfer for that channel is complete. The application must wait for the Channel Disabled interrupt before treating the channel as disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chdis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Chdis> for bool {
    #[inline(always)]
    fn from(variant: Chdis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chdis` reader - The application sets this bit to stop transmitting/receiving data on a channel, even before the transfer for that channel is complete. The application must wait for the Channel Disabled interrupt before treating the channel as disabled."]
pub type ChdisR = crate::BitReader<Chdis>;
impl ChdisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chdis {
        match self.bits {
            false => Chdis::Inactive,
            true => Chdis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Chdis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Chdis::Active
    }
}
#[doc = "Field `chdis` writer - The application sets this bit to stop transmitting/receiving data on a channel, even before the transfer for that channel is complete. The application must wait for the Channel Disabled interrupt before treating the channel as disabled."]
pub type ChdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When Scatter/Gather mode is disabled This field is set by the application and cleared by the OTG host. 0: Channel disabled 1: Channel enabled When Scatter/Gather mode is enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chena {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Chena> for bool {
    #[inline(always)]
    fn from(variant: Chena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chena` reader - When Scatter/Gather mode is disabled This field is set by the application and cleared by the OTG host. 0: Channel disabled 1: Channel enabled When Scatter/Gather mode is enabled."]
pub type ChenaR = crate::BitReader<Chena>;
impl ChenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chena {
        match self.bits {
            false => Chena::Inactive,
            true => Chena::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Chena::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Chena::Active
    }
}
#[doc = "Field `chena` writer - When Scatter/Gather mode is disabled This field is set by the application and cleared by the OTG host. 0: Channel disabled 1: Channel enabled When Scatter/Gather mode is enabled."]
pub type ChenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:10 - Indicates the maximum packet size of the associated endpoint."]
    #[inline(always)]
    pub fn mps(&self) -> MpsR {
        MpsR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bits 11:14 - Indicates the endpoint number on the device serving as the data source or sink."]
    #[inline(always)]
    pub fn epnum(&self) -> EpnumR {
        EpnumR::new(((self.bits >> 11) & 0x0f) as u8)
    }
    #[doc = "Bit 15 - Indicates whether the transaction is IN or OUT."]
    #[inline(always)]
    pub fn epdir(&self) -> EpdirR {
        EpdirR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - This field is set by the application to indicate that this channel is communicating to a low-speed device. The application must program this bit when a low speed device is connected to the host through an FS HUB. The HS OTG Host core uses this field to drive the XCVR_SELECT signal to 0x3 while communicating to the LS Device through the FS hub. In a peer to peer setup, the HS OTG Host core ignores this bit even if it is set by the application software"]
    #[inline(always)]
    pub fn lspddev(&self) -> LspddevR {
        LspddevR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - Indicates the transfer type selected."]
    #[inline(always)]
    pub fn eptype(&self) -> EptypeR {
        EptypeR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bits 20:21 - When the Split Enable bit of the Host Channel-n Split Control register (HCSPLTn.SpltEna) is reset (0), this field indicates to the host the number of transactions that must be executed per microframe for this periodic endpoint. for non periodic transfers, this field is used only in DMA mode, and specifies the number packets to be fetched for this channel before the internal DMA engine changes arbitration. When HCSPLTn.SpltEna is Set (1), this field indicates the number of immediate retries to be performed for a periodic split transactions on transaction errors. This field must be set to at least 1."]
    #[inline(always)]
    pub fn ec(&self) -> EcR {
        EcR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bits 22:28 - This field selects the specific device serving as the data source or sink."]
    #[inline(always)]
    pub fn devaddr(&self) -> DevaddrR {
        DevaddrR::new(((self.bits >> 22) & 0x7f) as u8)
    }
    #[doc = "Bit 30 - The application sets this bit to stop transmitting/receiving data on a channel, even before the transfer for that channel is complete. The application must wait for the Channel Disabled interrupt before treating the channel as disabled."]
    #[inline(always)]
    pub fn chdis(&self) -> ChdisR {
        ChdisR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - When Scatter/Gather mode is disabled This field is set by the application and cleared by the OTG host. 0: Channel disabled 1: Channel enabled When Scatter/Gather mode is enabled."]
    #[inline(always)]
    pub fn chena(&self) -> ChenaR {
        ChenaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:10 - Indicates the maximum packet size of the associated endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn mps(&mut self) -> MpsW<HostgrpHcchar9Spec> {
        MpsW::new(self, 0)
    }
    #[doc = "Bits 11:14 - Indicates the endpoint number on the device serving as the data source or sink."]
    #[inline(always)]
    #[must_use]
    pub fn epnum(&mut self) -> EpnumW<HostgrpHcchar9Spec> {
        EpnumW::new(self, 11)
    }
    #[doc = "Bit 15 - Indicates whether the transaction is IN or OUT."]
    #[inline(always)]
    #[must_use]
    pub fn epdir(&mut self) -> EpdirW<HostgrpHcchar9Spec> {
        EpdirW::new(self, 15)
    }
    #[doc = "Bit 17 - This field is set by the application to indicate that this channel is communicating to a low-speed device. The application must program this bit when a low speed device is connected to the host through an FS HUB. The HS OTG Host core uses this field to drive the XCVR_SELECT signal to 0x3 while communicating to the LS Device through the FS hub. In a peer to peer setup, the HS OTG Host core ignores this bit even if it is set by the application software"]
    #[inline(always)]
    #[must_use]
    pub fn lspddev(&mut self) -> LspddevW<HostgrpHcchar9Spec> {
        LspddevW::new(self, 17)
    }
    #[doc = "Bits 18:19 - Indicates the transfer type selected."]
    #[inline(always)]
    #[must_use]
    pub fn eptype(&mut self) -> EptypeW<HostgrpHcchar9Spec> {
        EptypeW::new(self, 18)
    }
    #[doc = "Bits 20:21 - When the Split Enable bit of the Host Channel-n Split Control register (HCSPLTn.SpltEna) is reset (0), this field indicates to the host the number of transactions that must be executed per microframe for this periodic endpoint. for non periodic transfers, this field is used only in DMA mode, and specifies the number packets to be fetched for this channel before the internal DMA engine changes arbitration. When HCSPLTn.SpltEna is Set (1), this field indicates the number of immediate retries to be performed for a periodic split transactions on transaction errors. This field must be set to at least 1."]
    #[inline(always)]
    #[must_use]
    pub fn ec(&mut self) -> EcW<HostgrpHcchar9Spec> {
        EcW::new(self, 20)
    }
    #[doc = "Bits 22:28 - This field selects the specific device serving as the data source or sink."]
    #[inline(always)]
    #[must_use]
    pub fn devaddr(&mut self) -> DevaddrW<HostgrpHcchar9Spec> {
        DevaddrW::new(self, 22)
    }
    #[doc = "Bit 30 - The application sets this bit to stop transmitting/receiving data on a channel, even before the transfer for that channel is complete. The application must wait for the Channel Disabled interrupt before treating the channel as disabled."]
    #[inline(always)]
    #[must_use]
    pub fn chdis(&mut self) -> ChdisW<HostgrpHcchar9Spec> {
        ChdisW::new(self, 30)
    }
    #[doc = "Bit 31 - When Scatter/Gather mode is disabled This field is set by the application and cleared by the OTG host. 0: Channel disabled 1: Channel enabled When Scatter/Gather mode is enabled."]
    #[inline(always)]
    #[must_use]
    pub fn chena(&mut self) -> ChenaW<HostgrpHcchar9Spec> {
        ChenaW::new(self, 31)
    }
}
#[doc = "Host Channel 9 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar9::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar9::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcchar9Spec;
impl crate::RegisterSpec for HostgrpHcchar9Spec {
    type Ux = u32;
    const OFFSET: u64 = 1568u64;
}
#[doc = "`read()` method returns [`hostgrp_hcchar9::R`](R) reader structure"]
impl crate::Readable for HostgrpHcchar9Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcchar9::W`](W) writer structure"]
impl crate::Writable for HostgrpHcchar9Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcchar9 to value 0"]
impl crate::Resettable for HostgrpHcchar9Spec {
    const RESET_VALUE: u32 = 0;
}
