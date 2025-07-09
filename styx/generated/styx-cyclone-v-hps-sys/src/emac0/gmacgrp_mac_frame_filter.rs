// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MAC_Frame_Filter` reader"]
pub type R = crate::R<GmacgrpMacFrameFilterSpec>;
#[doc = "Register `gmacgrp_MAC_Frame_Filter` writer"]
pub type W = crate::W<GmacgrpMacFrameFilterSpec>;
#[doc = "When this bit is set, the Address Filter block passes all incoming frames regardless of its destination or source address. The SA or DA Filter Fails status bits of the Receive Status Word are always cleared when PR is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pr {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Pr> for bool {
    #[inline(always)]
    fn from(variant: Pr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pr` reader - When this bit is set, the Address Filter block passes all incoming frames regardless of its destination or source address. The SA or DA Filter Fails status bits of the Receive Status Word are always cleared when PR is set."]
pub type PrR = crate::BitReader<Pr>;
impl PrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pr {
        match self.bits {
            true => Pr::Enabled,
            false => Pr::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Pr::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Pr::Disabled
    }
}
#[doc = "Field `pr` writer - When this bit is set, the Address Filter block passes all incoming frames regardless of its destination or source address. The SA or DA Filter Fails status bits of the Receive Status Word are always cleared when PR is set."]
pub type PrW<'a, REG> = crate::BitWriter<'a, REG, Pr>;
impl<'a, REG> PrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pr::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pr::Disabled)
    }
}
#[doc = "When set, MAC performs destination address filtering of unicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for unicast frames, that is, it compares the DA field with the values programmed in DA registers.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Huc {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Huc> for bool {
    #[inline(always)]
    fn from(variant: Huc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `huc` reader - When set, MAC performs destination address filtering of unicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for unicast frames, that is, it compares the DA field with the values programmed in DA registers."]
pub type HucR = crate::BitReader<Huc>;
impl HucR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Huc {
        match self.bits {
            true => Huc::Enabled,
            false => Huc::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Huc::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Huc::Disabled
    }
}
#[doc = "Field `huc` writer - When set, MAC performs destination address filtering of unicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for unicast frames, that is, it compares the DA field with the values programmed in DA registers."]
pub type HucW<'a, REG> = crate::BitWriter<'a, REG, Huc>;
impl<'a, REG> HucW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Huc::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Huc::Disabled)
    }
}
#[doc = "When set, MAC performs destination address filtering of received multicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for multicast frames, that is, it compares the DA field with the values programmed in DA registers.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hmc {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hmc> for bool {
    #[inline(always)]
    fn from(variant: Hmc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hmc` reader - When set, MAC performs destination address filtering of received multicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for multicast frames, that is, it compares the DA field with the values programmed in DA registers."]
pub type HmcR = crate::BitReader<Hmc>;
impl HmcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hmc {
        match self.bits {
            false => Hmc::Disabled,
            true => Hmc::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hmc::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hmc::Enabled
    }
}
#[doc = "Field `hmc` writer - When set, MAC performs destination address filtering of received multicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for multicast frames, that is, it compares the DA field with the values programmed in DA registers."]
pub type HmcW<'a, REG> = crate::BitWriter<'a, REG, Hmc>;
impl<'a, REG> HmcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hmc::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hmc::Enabled)
    }
}
#[doc = "When this bit is set, the Address Check block operates in inverse filtering mode for the DA address comparison for both unicast and multicast frames. When reset, normal filtering of frames is performed.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Daif {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Daif> for bool {
    #[inline(always)]
    fn from(variant: Daif) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `daif` reader - When this bit is set, the Address Check block operates in inverse filtering mode for the DA address comparison for both unicast and multicast frames. When reset, normal filtering of frames is performed."]
pub type DaifR = crate::BitReader<Daif>;
impl DaifR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Daif {
        match self.bits {
            false => Daif::Disabled,
            true => Daif::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Daif::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Daif::Enabled
    }
}
#[doc = "Field `daif` writer - When this bit is set, the Address Check block operates in inverse filtering mode for the DA address comparison for both unicast and multicast frames. When reset, normal filtering of frames is performed."]
pub type DaifW<'a, REG> = crate::BitWriter<'a, REG, Daif>;
impl<'a, REG> DaifW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Daif::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Daif::Enabled)
    }
}
#[doc = "When set, this bit indicates that all received frames with a multicast destination address (first bit in the destination address field is '1') are passed. When reset, filtering of multicast frame depends on HMC bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pm {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Pm> for bool {
    #[inline(always)]
    fn from(variant: Pm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pm` reader - When set, this bit indicates that all received frames with a multicast destination address (first bit in the destination address field is '1') are passed. When reset, filtering of multicast frame depends on HMC bit."]
pub type PmR = crate::BitReader<Pm>;
impl PmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pm {
        match self.bits {
            false => Pm::Disabled,
            true => Pm::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Pm::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Pm::Enabled
    }
}
#[doc = "Field `pm` writer - When set, this bit indicates that all received frames with a multicast destination address (first bit in the destination address field is '1') are passed. When reset, filtering of multicast frame depends on HMC bit."]
pub type PmW<'a, REG> = crate::BitWriter<'a, REG, Pm>;
impl<'a, REG> PmW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pm::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pm::Enabled)
    }
}
#[doc = "When this bit is set, the AFM block filters all incoming broadcast frames. In addition, it overrides all other filter settings. When this bit is reset, the AFM block passes all received broadcast frames.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dbf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dbf> for bool {
    #[inline(always)]
    fn from(variant: Dbf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dbf` reader - When this bit is set, the AFM block filters all incoming broadcast frames. In addition, it overrides all other filter settings. When this bit is reset, the AFM block passes all received broadcast frames."]
pub type DbfR = crate::BitReader<Dbf>;
impl DbfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dbf {
        match self.bits {
            false => Dbf::Disabled,
            true => Dbf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dbf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dbf::Enabled
    }
}
#[doc = "Field `dbf` writer - When this bit is set, the AFM block filters all incoming broadcast frames. In addition, it overrides all other filter settings. When this bit is reset, the AFM block passes all received broadcast frames."]
pub type DbfW<'a, REG> = crate::BitWriter<'a, REG, Dbf>;
impl<'a, REG> DbfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dbf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dbf::Enabled)
    }
}
#[doc = "These bits control the forwarding of all control frames (including unicast and multicast PAUSE frames). * 00: MAC filters all control frames from reaching the application. * 01: MAC forwards all control frames except PAUSE control frames to application even if they fail the Address filter. * 10: MAC forwards all control frames to application even if they fail the Address Filter. * 11: MAC forwards control frames that pass the Address Filter. The following conditions should be true for the PAUSE control frames processing: * Condition 1: The MAC is in the full-duplex mode and flow control is enabled by setting Bit 2 (RFE) of Register 6 (Flow Control Register) to 1. * Condition 2: The destination address (DA) of the received frame matches the special multicast address or the MAC Address 0 when Bit 3 (UP) of the Register 6 (Flow Control Register) is set. * Condition 3: The Type field of the received frame is 0x8808 and the OPCODE field is 0x0001. This field should be set to 01 only when the Condition 1 is true, that is, the MAC is programmed to operate in the full-duplex mode and the RFE bit is enabled. Otherwise, the PAUSE frame filtering may be inconsistent. When Condition 1 is false, the PAUSE frames are considered as generic control frames. Therefore, to pass all control frames (including PAUSE control frames) when the full-duplex mode and flow control is not enabled, you should set the PCF field to 10 or 11 (as required by the application).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pcf {
    #[doc = "0: `0`"]
    Macfltallcfr = 0,
    #[doc = "1: `1`"]
    Macfwdxpause = 1,
    #[doc = "2: `10`"]
    Macfwdfail = 2,
    #[doc = "3: `11`"]
    Macfwdpass = 3,
}
impl From<Pcf> for u8 {
    #[inline(always)]
    fn from(variant: Pcf) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Pcf {
    type Ux = u8;
}
#[doc = "Field `pcf` reader - These bits control the forwarding of all control frames (including unicast and multicast PAUSE frames). * 00: MAC filters all control frames from reaching the application. * 01: MAC forwards all control frames except PAUSE control frames to application even if they fail the Address filter. * 10: MAC forwards all control frames to application even if they fail the Address Filter. * 11: MAC forwards control frames that pass the Address Filter. The following conditions should be true for the PAUSE control frames processing: * Condition 1: The MAC is in the full-duplex mode and flow control is enabled by setting Bit 2 (RFE) of Register 6 (Flow Control Register) to 1. * Condition 2: The destination address (DA) of the received frame matches the special multicast address or the MAC Address 0 when Bit 3 (UP) of the Register 6 (Flow Control Register) is set. * Condition 3: The Type field of the received frame is 0x8808 and the OPCODE field is 0x0001. This field should be set to 01 only when the Condition 1 is true, that is, the MAC is programmed to operate in the full-duplex mode and the RFE bit is enabled. Otherwise, the PAUSE frame filtering may be inconsistent. When Condition 1 is false, the PAUSE frames are considered as generic control frames. Therefore, to pass all control frames (including PAUSE control frames) when the full-duplex mode and flow control is not enabled, you should set the PCF field to 10 or 11 (as required by the application)."]
pub type PcfR = crate::FieldReader<Pcf>;
impl PcfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pcf {
        match self.bits {
            0 => Pcf::Macfltallcfr,
            1 => Pcf::Macfwdxpause,
            2 => Pcf::Macfwdfail,
            3 => Pcf::Macfwdpass,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_macfltallcfr(&self) -> bool {
        *self == Pcf::Macfltallcfr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_macfwdxpause(&self) -> bool {
        *self == Pcf::Macfwdxpause
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_macfwdfail(&self) -> bool {
        *self == Pcf::Macfwdfail
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_macfwdpass(&self) -> bool {
        *self == Pcf::Macfwdpass
    }
}
#[doc = "Field `pcf` writer - These bits control the forwarding of all control frames (including unicast and multicast PAUSE frames). * 00: MAC filters all control frames from reaching the application. * 01: MAC forwards all control frames except PAUSE control frames to application even if they fail the Address filter. * 10: MAC forwards all control frames to application even if they fail the Address Filter. * 11: MAC forwards control frames that pass the Address Filter. The following conditions should be true for the PAUSE control frames processing: * Condition 1: The MAC is in the full-duplex mode and flow control is enabled by setting Bit 2 (RFE) of Register 6 (Flow Control Register) to 1. * Condition 2: The destination address (DA) of the received frame matches the special multicast address or the MAC Address 0 when Bit 3 (UP) of the Register 6 (Flow Control Register) is set. * Condition 3: The Type field of the received frame is 0x8808 and the OPCODE field is 0x0001. This field should be set to 01 only when the Condition 1 is true, that is, the MAC is programmed to operate in the full-duplex mode and the RFE bit is enabled. Otherwise, the PAUSE frame filtering may be inconsistent. When Condition 1 is false, the PAUSE frames are considered as generic control frames. Therefore, to pass all control frames (including PAUSE control frames) when the full-duplex mode and flow control is not enabled, you should set the PCF field to 10 or 11 (as required by the application)."]
pub type PcfW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Pcf>;
impl<'a, REG> PcfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn macfltallcfr(self) -> &'a mut crate::W<REG> {
        self.variant(Pcf::Macfltallcfr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn macfwdxpause(self) -> &'a mut crate::W<REG> {
        self.variant(Pcf::Macfwdxpause)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn macfwdfail(self) -> &'a mut crate::W<REG> {
        self.variant(Pcf::Macfwdfail)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn macfwdpass(self) -> &'a mut crate::W<REG> {
        self.variant(Pcf::Macfwdpass)
    }
}
#[doc = "When this bit is set, the Address Check block operates in inverse filtering mode for the SA address comparison. The frames whose SA matches the SA registers are marked as failing the SA Address filter. When this bit is reset, frames whose SA does not match the SA registers are marked as failing the SA Address filter.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Saif {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Saif> for bool {
    #[inline(always)]
    fn from(variant: Saif) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `saif` reader - When this bit is set, the Address Check block operates in inverse filtering mode for the SA address comparison. The frames whose SA matches the SA registers are marked as failing the SA Address filter. When this bit is reset, frames whose SA does not match the SA registers are marked as failing the SA Address filter."]
pub type SaifR = crate::BitReader<Saif>;
impl SaifR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Saif {
        match self.bits {
            false => Saif::Disabled,
            true => Saif::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Saif::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Saif::Enabled
    }
}
#[doc = "Field `saif` writer - When this bit is set, the Address Check block operates in inverse filtering mode for the SA address comparison. The frames whose SA matches the SA registers are marked as failing the SA Address filter. When this bit is reset, frames whose SA does not match the SA registers are marked as failing the SA Address filter."]
pub type SaifW<'a, REG> = crate::BitWriter<'a, REG, Saif>;
impl<'a, REG> SaifW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Saif::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Saif::Enabled)
    }
}
#[doc = "When this bit is set, the MAC compares the SA field of the received frames with the values programmed in the enabled SA registers. If the comparison matches, then the SA Match bit of RxStatus Word is set high. When this bit is set high and the SA filter fails, the MAC drops the frame. When this bit is reset, the MAC forwards the received frame to the application and with the updated SA Match bit of the RxStatus depending on the SA address comparison.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Saf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Saf> for bool {
    #[inline(always)]
    fn from(variant: Saf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `saf` reader - When this bit is set, the MAC compares the SA field of the received frames with the values programmed in the enabled SA registers. If the comparison matches, then the SA Match bit of RxStatus Word is set high. When this bit is set high and the SA filter fails, the MAC drops the frame. When this bit is reset, the MAC forwards the received frame to the application and with the updated SA Match bit of the RxStatus depending on the SA address comparison."]
pub type SafR = crate::BitReader<Saf>;
impl SafR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Saf {
        match self.bits {
            false => Saf::Disabled,
            true => Saf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Saf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Saf::Enabled
    }
}
#[doc = "Field `saf` writer - When this bit is set, the MAC compares the SA field of the received frames with the values programmed in the enabled SA registers. If the comparison matches, then the SA Match bit of RxStatus Word is set high. When this bit is set high and the SA filter fails, the MAC drops the frame. When this bit is reset, the MAC forwards the received frame to the application and with the updated SA Match bit of the RxStatus depending on the SA address comparison."]
pub type SafW<'a, REG> = crate::BitWriter<'a, REG, Saf>;
impl<'a, REG> SafW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Saf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Saf::Enabled)
    }
}
#[doc = "When this bit is set, it configures the address filter to pass a frame if it matches either the perfect filtering or the hash filtering as set by the HMC or HUC bits. When this bit is low and the HUC or HMC bit is set, the frame is passed only if it matches the Hash filter.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hpf {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hpf> for bool {
    #[inline(always)]
    fn from(variant: Hpf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hpf` reader - When this bit is set, it configures the address filter to pass a frame if it matches either the perfect filtering or the hash filtering as set by the HMC or HUC bits. When this bit is low and the HUC or HMC bit is set, the frame is passed only if it matches the Hash filter."]
pub type HpfR = crate::BitReader<Hpf>;
impl HpfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hpf {
        match self.bits {
            false => Hpf::Disabled,
            true => Hpf::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hpf::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hpf::Enabled
    }
}
#[doc = "Field `hpf` writer - When this bit is set, it configures the address filter to pass a frame if it matches either the perfect filtering or the hash filtering as set by the HMC or HUC bits. When this bit is low and the HUC or HMC bit is set, the frame is passed only if it matches the Hash filter."]
pub type HpfW<'a, REG> = crate::BitWriter<'a, REG, Hpf>;
impl<'a, REG> HpfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hpf::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hpf::Enabled)
    }
}
#[doc = "When set, this bit enables the MAC to drop VLAN tagged frames that do not match the VLAN Tag comparison. When reset, the MAC forwards all frames irrespective of the match status of the VLAN Tag.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vtfe {
    #[doc = "0: `0`"]
    Nodrop = 0,
    #[doc = "1: `1`"]
    Drop = 1,
}
impl From<Vtfe> for bool {
    #[inline(always)]
    fn from(variant: Vtfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vtfe` reader - When set, this bit enables the MAC to drop VLAN tagged frames that do not match the VLAN Tag comparison. When reset, the MAC forwards all frames irrespective of the match status of the VLAN Tag."]
pub type VtfeR = crate::BitReader<Vtfe>;
impl VtfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vtfe {
        match self.bits {
            false => Vtfe::Nodrop,
            true => Vtfe::Drop,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nodrop(&self) -> bool {
        *self == Vtfe::Nodrop
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_drop(&self) -> bool {
        *self == Vtfe::Drop
    }
}
#[doc = "Field `vtfe` writer - When set, this bit enables the MAC to drop VLAN tagged frames that do not match the VLAN Tag comparison. When reset, the MAC forwards all frames irrespective of the match status of the VLAN Tag."]
pub type VtfeW<'a, REG> = crate::BitWriter<'a, REG, Vtfe>;
impl<'a, REG> VtfeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nodrop(self) -> &'a mut crate::W<REG> {
        self.variant(Vtfe::Nodrop)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn drop(self) -> &'a mut crate::W<REG> {
        self.variant(Vtfe::Drop)
    }
}
#[doc = "When set, this bit enables the MAC to drop frames that do not match the enabled Layer 3 and Layer 4 filters. If Layer 3 or Layer 4 filters are not enabled for matching, this bit does not have any effect. When reset, the MAC forwards all frames irrespective of the match status of the Layer 3 and Layer 4 filters.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipfe {
    #[doc = "0: `0`"]
    Nodrop = 0,
    #[doc = "1: `1`"]
    Drop = 1,
}
impl From<Ipfe> for bool {
    #[inline(always)]
    fn from(variant: Ipfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ipfe` reader - When set, this bit enables the MAC to drop frames that do not match the enabled Layer 3 and Layer 4 filters. If Layer 3 or Layer 4 filters are not enabled for matching, this bit does not have any effect. When reset, the MAC forwards all frames irrespective of the match status of the Layer 3 and Layer 4 filters."]
pub type IpfeR = crate::BitReader<Ipfe>;
impl IpfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ipfe {
        match self.bits {
            false => Ipfe::Nodrop,
            true => Ipfe::Drop,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nodrop(&self) -> bool {
        *self == Ipfe::Nodrop
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_drop(&self) -> bool {
        *self == Ipfe::Drop
    }
}
#[doc = "Field `ipfe` writer - When set, this bit enables the MAC to drop frames that do not match the enabled Layer 3 and Layer 4 filters. If Layer 3 or Layer 4 filters are not enabled for matching, this bit does not have any effect. When reset, the MAC forwards all frames irrespective of the match status of the Layer 3 and Layer 4 filters."]
pub type IpfeW<'a, REG> = crate::BitWriter<'a, REG, Ipfe>;
impl<'a, REG> IpfeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nodrop(self) -> &'a mut crate::W<REG> {
        self.variant(Ipfe::Nodrop)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn drop(self) -> &'a mut crate::W<REG> {
        self.variant(Ipfe::Drop)
    }
}
#[doc = "When set, this bit enables the MAC to drop the non-TCP or UDP over IP frames. The MAC forward only those frames that are processed by the Layer 4 filter. When reset, this bit enables the MAC to forward all non-TCP or UDP over IP frames.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dntu {
    #[doc = "0: `0`"]
    Nodrop = 0,
    #[doc = "1: `1`"]
    Drop = 1,
}
impl From<Dntu> for bool {
    #[inline(always)]
    fn from(variant: Dntu) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dntu` reader - When set, this bit enables the MAC to drop the non-TCP or UDP over IP frames. The MAC forward only those frames that are processed by the Layer 4 filter. When reset, this bit enables the MAC to forward all non-TCP or UDP over IP frames."]
pub type DntuR = crate::BitReader<Dntu>;
impl DntuR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dntu {
        match self.bits {
            false => Dntu::Nodrop,
            true => Dntu::Drop,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nodrop(&self) -> bool {
        *self == Dntu::Nodrop
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_drop(&self) -> bool {
        *self == Dntu::Drop
    }
}
#[doc = "Field `dntu` writer - When set, this bit enables the MAC to drop the non-TCP or UDP over IP frames. The MAC forward only those frames that are processed by the Layer 4 filter. When reset, this bit enables the MAC to forward all non-TCP or UDP over IP frames."]
pub type DntuW<'a, REG> = crate::BitWriter<'a, REG, Dntu>;
impl<'a, REG> DntuW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nodrop(self) -> &'a mut crate::W<REG> {
        self.variant(Dntu::Nodrop)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn drop(self) -> &'a mut crate::W<REG> {
        self.variant(Dntu::Drop)
    }
}
#[doc = "When this bit is set, the MAC Receiver block passes all received frames, irrespective of whether they pass the address filter or not, to the Application. The result of the SA or DA filtering is updated (pass or fail) in the corresponding bits in the Receive Status Word. When this bit is reset, the Receiver block passes only those frames to the Application that pass the SA or DA address filter.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ra {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ra> for bool {
    #[inline(always)]
    fn from(variant: Ra) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ra` reader - When this bit is set, the MAC Receiver block passes all received frames, irrespective of whether they pass the address filter or not, to the Application. The result of the SA or DA filtering is updated (pass or fail) in the corresponding bits in the Receive Status Word. When this bit is reset, the Receiver block passes only those frames to the Application that pass the SA or DA address filter."]
pub type RaR = crate::BitReader<Ra>;
impl RaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ra {
        match self.bits {
            false => Ra::Disabled,
            true => Ra::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ra::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ra::Enabled
    }
}
#[doc = "Field `ra` writer - When this bit is set, the MAC Receiver block passes all received frames, irrespective of whether they pass the address filter or not, to the Application. The result of the SA or DA filtering is updated (pass or fail) in the corresponding bits in the Receive Status Word. When this bit is reset, the Receiver block passes only those frames to the Application that pass the SA or DA address filter."]
pub type RaW<'a, REG> = crate::BitWriter<'a, REG, Ra>;
impl<'a, REG> RaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ra::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ra::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When this bit is set, the Address Filter block passes all incoming frames regardless of its destination or source address. The SA or DA Filter Fails status bits of the Receive Status Word are always cleared when PR is set."]
    #[inline(always)]
    pub fn pr(&self) -> PrR {
        PrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set, MAC performs destination address filtering of unicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for unicast frames, that is, it compares the DA field with the values programmed in DA registers."]
    #[inline(always)]
    pub fn huc(&self) -> HucR {
        HucR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When set, MAC performs destination address filtering of received multicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for multicast frames, that is, it compares the DA field with the values programmed in DA registers."]
    #[inline(always)]
    pub fn hmc(&self) -> HmcR {
        HmcR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When this bit is set, the Address Check block operates in inverse filtering mode for the DA address comparison for both unicast and multicast frames. When reset, normal filtering of frames is performed."]
    #[inline(always)]
    pub fn daif(&self) -> DaifR {
        DaifR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When set, this bit indicates that all received frames with a multicast destination address (first bit in the destination address field is '1') are passed. When reset, filtering of multicast frame depends on HMC bit."]
    #[inline(always)]
    pub fn pm(&self) -> PmR {
        PmR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When this bit is set, the AFM block filters all incoming broadcast frames. In addition, it overrides all other filter settings. When this bit is reset, the AFM block passes all received broadcast frames."]
    #[inline(always)]
    pub fn dbf(&self) -> DbfR {
        DbfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:7 - These bits control the forwarding of all control frames (including unicast and multicast PAUSE frames). * 00: MAC filters all control frames from reaching the application. * 01: MAC forwards all control frames except PAUSE control frames to application even if they fail the Address filter. * 10: MAC forwards all control frames to application even if they fail the Address Filter. * 11: MAC forwards control frames that pass the Address Filter. The following conditions should be true for the PAUSE control frames processing: * Condition 1: The MAC is in the full-duplex mode and flow control is enabled by setting Bit 2 (RFE) of Register 6 (Flow Control Register) to 1. * Condition 2: The destination address (DA) of the received frame matches the special multicast address or the MAC Address 0 when Bit 3 (UP) of the Register 6 (Flow Control Register) is set. * Condition 3: The Type field of the received frame is 0x8808 and the OPCODE field is 0x0001. This field should be set to 01 only when the Condition 1 is true, that is, the MAC is programmed to operate in the full-duplex mode and the RFE bit is enabled. Otherwise, the PAUSE frame filtering may be inconsistent. When Condition 1 is false, the PAUSE frames are considered as generic control frames. Therefore, to pass all control frames (including PAUSE control frames) when the full-duplex mode and flow control is not enabled, you should set the PCF field to 10 or 11 (as required by the application)."]
    #[inline(always)]
    pub fn pcf(&self) -> PcfR {
        PcfR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bit 8 - When this bit is set, the Address Check block operates in inverse filtering mode for the SA address comparison. The frames whose SA matches the SA registers are marked as failing the SA Address filter. When this bit is reset, frames whose SA does not match the SA registers are marked as failing the SA Address filter."]
    #[inline(always)]
    pub fn saif(&self) -> SaifR {
        SaifR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - When this bit is set, the MAC compares the SA field of the received frames with the values programmed in the enabled SA registers. If the comparison matches, then the SA Match bit of RxStatus Word is set high. When this bit is set high and the SA filter fails, the MAC drops the frame. When this bit is reset, the MAC forwards the received frame to the application and with the updated SA Match bit of the RxStatus depending on the SA address comparison."]
    #[inline(always)]
    pub fn saf(&self) -> SafR {
        SafR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - When this bit is set, it configures the address filter to pass a frame if it matches either the perfect filtering or the hash filtering as set by the HMC or HUC bits. When this bit is low and the HUC or HMC bit is set, the frame is passed only if it matches the Hash filter."]
    #[inline(always)]
    pub fn hpf(&self) -> HpfR {
        HpfR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 16 - When set, this bit enables the MAC to drop VLAN tagged frames that do not match the VLAN Tag comparison. When reset, the MAC forwards all frames irrespective of the match status of the VLAN Tag."]
    #[inline(always)]
    pub fn vtfe(&self) -> VtfeR {
        VtfeR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 20 - When set, this bit enables the MAC to drop frames that do not match the enabled Layer 3 and Layer 4 filters. If Layer 3 or Layer 4 filters are not enabled for matching, this bit does not have any effect. When reset, the MAC forwards all frames irrespective of the match status of the Layer 3 and Layer 4 filters."]
    #[inline(always)]
    pub fn ipfe(&self) -> IpfeR {
        IpfeR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - When set, this bit enables the MAC to drop the non-TCP or UDP over IP frames. The MAC forward only those frames that are processed by the Layer 4 filter. When reset, this bit enables the MAC to forward all non-TCP or UDP over IP frames."]
    #[inline(always)]
    pub fn dntu(&self) -> DntuR {
        DntuR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 31 - When this bit is set, the MAC Receiver block passes all received frames, irrespective of whether they pass the address filter or not, to the Application. The result of the SA or DA filtering is updated (pass or fail) in the corresponding bits in the Receive Status Word. When this bit is reset, the Receiver block passes only those frames to the Application that pass the SA or DA address filter."]
    #[inline(always)]
    pub fn ra(&self) -> RaR {
        RaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is set, the Address Filter block passes all incoming frames regardless of its destination or source address. The SA or DA Filter Fails status bits of the Receive Status Word are always cleared when PR is set."]
    #[inline(always)]
    #[must_use]
    pub fn pr(&mut self) -> PrW<GmacgrpMacFrameFilterSpec> {
        PrW::new(self, 0)
    }
    #[doc = "Bit 1 - When set, MAC performs destination address filtering of unicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for unicast frames, that is, it compares the DA field with the values programmed in DA registers."]
    #[inline(always)]
    #[must_use]
    pub fn huc(&mut self) -> HucW<GmacgrpMacFrameFilterSpec> {
        HucW::new(self, 1)
    }
    #[doc = "Bit 2 - When set, MAC performs destination address filtering of received multicast frames according to the hash table. When reset, the MAC performs a perfect destination address filtering for multicast frames, that is, it compares the DA field with the values programmed in DA registers."]
    #[inline(always)]
    #[must_use]
    pub fn hmc(&mut self) -> HmcW<GmacgrpMacFrameFilterSpec> {
        HmcW::new(self, 2)
    }
    #[doc = "Bit 3 - When this bit is set, the Address Check block operates in inverse filtering mode for the DA address comparison for both unicast and multicast frames. When reset, normal filtering of frames is performed."]
    #[inline(always)]
    #[must_use]
    pub fn daif(&mut self) -> DaifW<GmacgrpMacFrameFilterSpec> {
        DaifW::new(self, 3)
    }
    #[doc = "Bit 4 - When set, this bit indicates that all received frames with a multicast destination address (first bit in the destination address field is '1') are passed. When reset, filtering of multicast frame depends on HMC bit."]
    #[inline(always)]
    #[must_use]
    pub fn pm(&mut self) -> PmW<GmacgrpMacFrameFilterSpec> {
        PmW::new(self, 4)
    }
    #[doc = "Bit 5 - When this bit is set, the AFM block filters all incoming broadcast frames. In addition, it overrides all other filter settings. When this bit is reset, the AFM block passes all received broadcast frames."]
    #[inline(always)]
    #[must_use]
    pub fn dbf(&mut self) -> DbfW<GmacgrpMacFrameFilterSpec> {
        DbfW::new(self, 5)
    }
    #[doc = "Bits 6:7 - These bits control the forwarding of all control frames (including unicast and multicast PAUSE frames). * 00: MAC filters all control frames from reaching the application. * 01: MAC forwards all control frames except PAUSE control frames to application even if they fail the Address filter. * 10: MAC forwards all control frames to application even if they fail the Address Filter. * 11: MAC forwards control frames that pass the Address Filter. The following conditions should be true for the PAUSE control frames processing: * Condition 1: The MAC is in the full-duplex mode and flow control is enabled by setting Bit 2 (RFE) of Register 6 (Flow Control Register) to 1. * Condition 2: The destination address (DA) of the received frame matches the special multicast address or the MAC Address 0 when Bit 3 (UP) of the Register 6 (Flow Control Register) is set. * Condition 3: The Type field of the received frame is 0x8808 and the OPCODE field is 0x0001. This field should be set to 01 only when the Condition 1 is true, that is, the MAC is programmed to operate in the full-duplex mode and the RFE bit is enabled. Otherwise, the PAUSE frame filtering may be inconsistent. When Condition 1 is false, the PAUSE frames are considered as generic control frames. Therefore, to pass all control frames (including PAUSE control frames) when the full-duplex mode and flow control is not enabled, you should set the PCF field to 10 or 11 (as required by the application)."]
    #[inline(always)]
    #[must_use]
    pub fn pcf(&mut self) -> PcfW<GmacgrpMacFrameFilterSpec> {
        PcfW::new(self, 6)
    }
    #[doc = "Bit 8 - When this bit is set, the Address Check block operates in inverse filtering mode for the SA address comparison. The frames whose SA matches the SA registers are marked as failing the SA Address filter. When this bit is reset, frames whose SA does not match the SA registers are marked as failing the SA Address filter."]
    #[inline(always)]
    #[must_use]
    pub fn saif(&mut self) -> SaifW<GmacgrpMacFrameFilterSpec> {
        SaifW::new(self, 8)
    }
    #[doc = "Bit 9 - When this bit is set, the MAC compares the SA field of the received frames with the values programmed in the enabled SA registers. If the comparison matches, then the SA Match bit of RxStatus Word is set high. When this bit is set high and the SA filter fails, the MAC drops the frame. When this bit is reset, the MAC forwards the received frame to the application and with the updated SA Match bit of the RxStatus depending on the SA address comparison."]
    #[inline(always)]
    #[must_use]
    pub fn saf(&mut self) -> SafW<GmacgrpMacFrameFilterSpec> {
        SafW::new(self, 9)
    }
    #[doc = "Bit 10 - When this bit is set, it configures the address filter to pass a frame if it matches either the perfect filtering or the hash filtering as set by the HMC or HUC bits. When this bit is low and the HUC or HMC bit is set, the frame is passed only if it matches the Hash filter."]
    #[inline(always)]
    #[must_use]
    pub fn hpf(&mut self) -> HpfW<GmacgrpMacFrameFilterSpec> {
        HpfW::new(self, 10)
    }
    #[doc = "Bit 16 - When set, this bit enables the MAC to drop VLAN tagged frames that do not match the VLAN Tag comparison. When reset, the MAC forwards all frames irrespective of the match status of the VLAN Tag."]
    #[inline(always)]
    #[must_use]
    pub fn vtfe(&mut self) -> VtfeW<GmacgrpMacFrameFilterSpec> {
        VtfeW::new(self, 16)
    }
    #[doc = "Bit 20 - When set, this bit enables the MAC to drop frames that do not match the enabled Layer 3 and Layer 4 filters. If Layer 3 or Layer 4 filters are not enabled for matching, this bit does not have any effect. When reset, the MAC forwards all frames irrespective of the match status of the Layer 3 and Layer 4 filters."]
    #[inline(always)]
    #[must_use]
    pub fn ipfe(&mut self) -> IpfeW<GmacgrpMacFrameFilterSpec> {
        IpfeW::new(self, 20)
    }
    #[doc = "Bit 21 - When set, this bit enables the MAC to drop the non-TCP or UDP over IP frames. The MAC forward only those frames that are processed by the Layer 4 filter. When reset, this bit enables the MAC to forward all non-TCP or UDP over IP frames."]
    #[inline(always)]
    #[must_use]
    pub fn dntu(&mut self) -> DntuW<GmacgrpMacFrameFilterSpec> {
        DntuW::new(self, 21)
    }
    #[doc = "Bit 31 - When this bit is set, the MAC Receiver block passes all received frames, irrespective of whether they pass the address filter or not, to the Application. The result of the SA or DA filtering is updated (pass or fail) in the corresponding bits in the Receive Status Word. When this bit is reset, the Receiver block passes only those frames to the Application that pass the SA or DA address filter."]
    #[inline(always)]
    #[must_use]
    pub fn ra(&mut self) -> RaW<GmacgrpMacFrameFilterSpec> {
        RaW::new(self, 31)
    }
}
#[doc = "The MAC Frame Filter register contains the filter controls for receiving frames. Some of the controls from this register go to the address check block of the MAC, which performs the first level of address filtering. The second level of filtering is performed on the incoming frame, based on other controls such as Pass Bad Frames and Pass Control Frames.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_frame_filter::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_frame_filter::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMacFrameFilterSpec;
impl crate::RegisterSpec for GmacgrpMacFrameFilterSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`gmacgrp_mac_frame_filter::R`](R) reader structure"]
impl crate::Readable for GmacgrpMacFrameFilterSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mac_frame_filter::W`](W) writer structure"]
impl crate::Writable for GmacgrpMacFrameFilterSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MAC_Frame_Filter to value 0"]
impl crate::Resettable for GmacgrpMacFrameFilterSpec {
    const RESET_VALUE: u32 = 0;
}
