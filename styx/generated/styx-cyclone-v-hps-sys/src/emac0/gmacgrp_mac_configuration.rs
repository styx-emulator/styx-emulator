// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MAC_Configuration` reader"]
pub type R = crate::R<GmacgrpMacConfigurationSpec>;
#[doc = "Register `gmacgrp_MAC_Configuration` writer"]
pub type W = crate::W<GmacgrpMacConfigurationSpec>;
#[doc = "These bits control the number of preamble bytes that are added to the beginning of every Transmit frame. The preamble reduction occurs only when the MAC is operating\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Prelen {
    #[doc = "0: `0`"]
    Pream7bytes = 0,
    #[doc = "1: `1`"]
    Pream5bytes = 1,
    #[doc = "2: `10`"]
    Pream3bytes = 2,
}
impl From<Prelen> for u8 {
    #[inline(always)]
    fn from(variant: Prelen) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Prelen {
    type Ux = u8;
}
#[doc = "Field `prelen` reader - These bits control the number of preamble bytes that are added to the beginning of every Transmit frame. The preamble reduction occurs only when the MAC is operating"]
pub type PrelenR = crate::FieldReader<Prelen>;
impl PrelenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Prelen> {
        match self.bits {
            0 => Some(Prelen::Pream7bytes),
            1 => Some(Prelen::Pream5bytes),
            2 => Some(Prelen::Pream3bytes),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_pream7bytes(&self) -> bool {
        *self == Prelen::Pream7bytes
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pream5bytes(&self) -> bool {
        *self == Prelen::Pream5bytes
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_pream3bytes(&self) -> bool {
        *self == Prelen::Pream3bytes
    }
}
#[doc = "Field `prelen` writer - These bits control the number of preamble bytes that are added to the beginning of every Transmit frame. The preamble reduction occurs only when the MAC is operating"]
pub type PrelenW<'a, REG> = crate::FieldWriter<'a, REG, 2, Prelen>;
impl<'a, REG> PrelenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn pream7bytes(self) -> &'a mut crate::W<REG> {
        self.variant(Prelen::Pream7bytes)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pream5bytes(self) -> &'a mut crate::W<REG> {
        self.variant(Prelen::Pream5bytes)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn pream3bytes(self) -> &'a mut crate::W<REG> {
        self.variant(Prelen::Pream3bytes)
    }
}
#[doc = "When this bit is set, the receiver state machine of the MAC is enabled for receiving frames from the GMII or MII. When this bit is reset, the MAC receive state machine is disabled after the completion of the reception of the current frame, and does not receive any further frames from the GMII or MII.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Re {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Re> for bool {
    #[inline(always)]
    fn from(variant: Re) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `re` reader - When this bit is set, the receiver state machine of the MAC is enabled for receiving frames from the GMII or MII. When this bit is reset, the MAC receive state machine is disabled after the completion of the reception of the current frame, and does not receive any further frames from the GMII or MII."]
pub type ReR = crate::BitReader<Re>;
impl ReR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Re {
        match self.bits {
            false => Re::Disabled,
            true => Re::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Re::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Re::Enabled
    }
}
#[doc = "Field `re` writer - When this bit is set, the receiver state machine of the MAC is enabled for receiving frames from the GMII or MII. When this bit is reset, the MAC receive state machine is disabled after the completion of the reception of the current frame, and does not receive any further frames from the GMII or MII."]
pub type ReW<'a, REG> = crate::BitWriter<'a, REG, Re>;
impl<'a, REG> ReW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Re::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Re::Enabled)
    }
}
#[doc = "When this bit is set, the transmit state machine of the MAC is enabled for transmission on the GMII or MII. When this bit is reset, the MAC transmit state machine is disabled after the completion of the transmission of the current frame, and does not transmit any further frames.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Te {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Te> for bool {
    #[inline(always)]
    fn from(variant: Te) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `te` reader - When this bit is set, the transmit state machine of the MAC is enabled for transmission on the GMII or MII. When this bit is reset, the MAC transmit state machine is disabled after the completion of the transmission of the current frame, and does not transmit any further frames."]
pub type TeR = crate::BitReader<Te>;
impl TeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Te {
        match self.bits {
            false => Te::Disabled,
            true => Te::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Te::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Te::Enabled
    }
}
#[doc = "Field `te` writer - When this bit is set, the transmit state machine of the MAC is enabled for transmission on the GMII or MII. When this bit is reset, the MAC transmit state machine is disabled after the completion of the transmission of the current frame, and does not transmit any further frames."]
pub type TeW<'a, REG> = crate::BitWriter<'a, REG, Te>;
impl<'a, REG> TeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Te::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Te::Enabled)
    }
}
#[doc = "When this bit is set, the deferral check function is enabled in the MAC. The MAC issues a Frame Abort status, along with the excessive deferral error bit set in the transmit frame status, when the transmit state machine is deferred for more than 24,288 bit times in the 10 or 100 Mbps mode. If the MAC is configured for 1000 Mbps operation, or if the Jumbo frame mode is enabled in the 10 or 100 Mbps mode, the threshold for deferral is 155,680 bits times. Deferral begins when the transmitter is ready to transmit, but is prevented because of an active carrier sense signal (CRS) on GMII or MII. Defer time is not cumulative. When the transmitter defers for 10,000 bit times, it transmits, collides, backs off, and then defers again after completion of back-off. The deferral timer resets to 0 and restarts. When this bit is reset, the deferral check function is disabled and the MAC defers until the CRS signal goes inactive. This bit is applicable only in the half-duplex mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dc {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Dc> for bool {
    #[inline(always)]
    fn from(variant: Dc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dc` reader - When this bit is set, the deferral check function is enabled in the MAC. The MAC issues a Frame Abort status, along with the excessive deferral error bit set in the transmit frame status, when the transmit state machine is deferred for more than 24,288 bit times in the 10 or 100 Mbps mode. If the MAC is configured for 1000 Mbps operation, or if the Jumbo frame mode is enabled in the 10 or 100 Mbps mode, the threshold for deferral is 155,680 bits times. Deferral begins when the transmitter is ready to transmit, but is prevented because of an active carrier sense signal (CRS) on GMII or MII. Defer time is not cumulative. When the transmitter defers for 10,000 bit times, it transmits, collides, backs off, and then defers again after completion of back-off. The deferral timer resets to 0 and restarts. When this bit is reset, the deferral check function is disabled and the MAC defers until the CRS signal goes inactive. This bit is applicable only in the half-duplex mode."]
pub type DcR = crate::BitReader<Dc>;
impl DcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dc {
        match self.bits {
            true => Dc::Enabled,
            false => Dc::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dc::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dc::Disabled
    }
}
#[doc = "Field `dc` writer - When this bit is set, the deferral check function is enabled in the MAC. The MAC issues a Frame Abort status, along with the excessive deferral error bit set in the transmit frame status, when the transmit state machine is deferred for more than 24,288 bit times in the 10 or 100 Mbps mode. If the MAC is configured for 1000 Mbps operation, or if the Jumbo frame mode is enabled in the 10 or 100 Mbps mode, the threshold for deferral is 155,680 bits times. Deferral begins when the transmitter is ready to transmit, but is prevented because of an active carrier sense signal (CRS) on GMII or MII. Defer time is not cumulative. When the transmitter defers for 10,000 bit times, it transmits, collides, backs off, and then defers again after completion of back-off. The deferral timer resets to 0 and restarts. When this bit is reset, the deferral check function is disabled and the MAC defers until the CRS signal goes inactive. This bit is applicable only in the half-duplex mode."]
pub type DcW<'a, REG> = crate::BitWriter<'a, REG, Dc>;
impl<'a, REG> DcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dc::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dc::Disabled)
    }
}
#[doc = "The Back-Off limit determines the random integer number (r) of slot time delays (4,096 bit times for 1000 Mbps and 512 bit times for 10/100 Mbps) for which the MAC waits before rescheduling a transmission attempt during retries after a collision. This bit is applicable only in the half-duplex mode. * 00: k = min (n, 10) * 01: k = min (n, 8) * 10: k = min (n, 4) * 11: k = min (n, 1) where &lt;i> n &lt;/i>= retransmission attempt. The random integer &lt;i> r &lt;/i> takes the value in the range 0 &lt;= r &lt; kth power of 2\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Bl {
    #[doc = "0: `0`"]
    Backlimtr10 = 0,
    #[doc = "1: `1`"]
    Backlimirt8 = 1,
    #[doc = "2: `10`"]
    Backlimitr4 = 2,
    #[doc = "3: `11`"]
    Backlimitr1 = 3,
}
impl From<Bl> for u8 {
    #[inline(always)]
    fn from(variant: Bl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Bl {
    type Ux = u8;
}
#[doc = "Field `bl` reader - The Back-Off limit determines the random integer number (r) of slot time delays (4,096 bit times for 1000 Mbps and 512 bit times for 10/100 Mbps) for which the MAC waits before rescheduling a transmission attempt during retries after a collision. This bit is applicable only in the half-duplex mode. * 00: k = min (n, 10) * 01: k = min (n, 8) * 10: k = min (n, 4) * 11: k = min (n, 1) where &lt;i> n &lt;/i>= retransmission attempt. The random integer &lt;i> r &lt;/i> takes the value in the range 0 &lt;= r &lt; kth power of 2"]
pub type BlR = crate::FieldReader<Bl>;
impl BlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bl {
        match self.bits {
            0 => Bl::Backlimtr10,
            1 => Bl::Backlimirt8,
            2 => Bl::Backlimitr4,
            3 => Bl::Backlimitr1,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_backlimtr10(&self) -> bool {
        *self == Bl::Backlimtr10
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_backlimirt8(&self) -> bool {
        *self == Bl::Backlimirt8
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_backlimitr4(&self) -> bool {
        *self == Bl::Backlimitr4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_backlimitr1(&self) -> bool {
        *self == Bl::Backlimitr1
    }
}
#[doc = "Field `bl` writer - The Back-Off limit determines the random integer number (r) of slot time delays (4,096 bit times for 1000 Mbps and 512 bit times for 10/100 Mbps) for which the MAC waits before rescheduling a transmission attempt during retries after a collision. This bit is applicable only in the half-duplex mode. * 00: k = min (n, 10) * 01: k = min (n, 8) * 10: k = min (n, 4) * 11: k = min (n, 1) where &lt;i> n &lt;/i>= retransmission attempt. The random integer &lt;i> r &lt;/i> takes the value in the range 0 &lt;= r &lt; kth power of 2"]
pub type BlW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Bl>;
impl<'a, REG> BlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn backlimtr10(self) -> &'a mut crate::W<REG> {
        self.variant(Bl::Backlimtr10)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn backlimirt8(self) -> &'a mut crate::W<REG> {
        self.variant(Bl::Backlimirt8)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn backlimitr4(self) -> &'a mut crate::W<REG> {
        self.variant(Bl::Backlimitr4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn backlimitr1(self) -> &'a mut crate::W<REG> {
        self.variant(Bl::Backlimitr1)
    }
}
#[doc = "When this bit is set, the MAC strips the Pad or FCS field on the incoming frames only if the value of the length field is less than 1,536 bytes. All received frames with length field greater than or equal to 1,536 bytes are passed to the application without stripping the Pad or FCS field. When this bit is reset, the MAC passes all incoming frames, without modifying them, to the Host.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acs {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Acs> for bool {
    #[inline(always)]
    fn from(variant: Acs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `acs` reader - When this bit is set, the MAC strips the Pad or FCS field on the incoming frames only if the value of the length field is less than 1,536 bytes. All received frames with length field greater than or equal to 1,536 bytes are passed to the application without stripping the Pad or FCS field. When this bit is reset, the MAC passes all incoming frames, without modifying them, to the Host."]
pub type AcsR = crate::BitReader<Acs>;
impl AcsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Acs {
        match self.bits {
            false => Acs::Disabled,
            true => Acs::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Acs::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Acs::Enabled
    }
}
#[doc = "Field `acs` writer - When this bit is set, the MAC strips the Pad or FCS field on the incoming frames only if the value of the length field is less than 1,536 bytes. All received frames with length field greater than or equal to 1,536 bytes are passed to the application without stripping the Pad or FCS field. When this bit is reset, the MAC passes all incoming frames, without modifying them, to the Host."]
pub type AcsW<'a, REG> = crate::BitWriter<'a, REG, Acs>;
impl<'a, REG> AcsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Acs::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Acs::Enabled)
    }
}
#[doc = "This bit indicates whether the link is up or down during the transmission of configuration in the RGMII, SGMII, or SMII interface\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lud {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lud> for bool {
    #[inline(always)]
    fn from(variant: Lud) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lud` reader - This bit indicates whether the link is up or down during the transmission of configuration in the RGMII, SGMII, or SMII interface"]
pub type LudR = crate::BitReader<Lud>;
impl LudR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lud {
        match self.bits {
            false => Lud::Disabled,
            true => Lud::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lud::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lud::Enabled
    }
}
#[doc = "Field `lud` writer - This bit indicates whether the link is up or down during the transmission of configuration in the RGMII, SGMII, or SMII interface"]
pub type LudW<'a, REG> = crate::BitWriter<'a, REG, Lud>;
impl<'a, REG> LudW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lud::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lud::Enabled)
    }
}
#[doc = "When this bit is set, the MAC attempts only one transmission. When a collision occurs on the GMII or MII interface, the MAC ignores the current frame transmission and reports a Frame Abort with excessive collision error in the transmit frame status. When this bit is reset, the MAC attempts retries based on the settings of the BL field (Bits \\[6:5\\]). This bit is applicable only in the half-duplex mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dr {
    #[doc = "1: `1`"]
    Disabled = 1,
    #[doc = "0: `0`"]
    Enabled = 0,
}
impl From<Dr> for bool {
    #[inline(always)]
    fn from(variant: Dr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dr` reader - When this bit is set, the MAC attempts only one transmission. When a collision occurs on the GMII or MII interface, the MAC ignores the current frame transmission and reports a Frame Abort with excessive collision error in the transmit frame status. When this bit is reset, the MAC attempts retries based on the settings of the BL field (Bits \\[6:5\\]). This bit is applicable only in the half-duplex mode."]
pub type DrR = crate::BitReader<Dr>;
impl DrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dr {
        match self.bits {
            true => Dr::Disabled,
            false => Dr::Enabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dr::Disabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dr::Enabled
    }
}
#[doc = "Field `dr` writer - When this bit is set, the MAC attempts only one transmission. When a collision occurs on the GMII or MII interface, the MAC ignores the current frame transmission and reports a Frame Abort with excessive collision error in the transmit frame status. When this bit is reset, the MAC attempts retries based on the settings of the BL field (Bits \\[6:5\\]). This bit is applicable only in the half-duplex mode."]
pub type DrW<'a, REG> = crate::BitWriter<'a, REG, Dr>;
impl<'a, REG> DrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dr::Disabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dr::Enabled)
    }
}
#[doc = "When this bit is set, the MAC calculates the 16-bit ones complement of the ones complement sum of all received Ethernet frame payloads. It also checks whether the IPv4 Header checksum (assumed to be bytes 2526 or 2930 (VLAN-tagged) of the received Ethernet frame) is correct for the received frame and gives the status in the receive status word. The MAC also appends the 16-bit checksum calculated for the IP header datagram payload (bytes after the IPv4 header) and appends it to the Ethernet frame transferred to the application (when Type 2 COE is deselected). When this bit is reset, this function is disabled. When Type 2 COE is selected, this bit, when set, enables the IPv4 header checksum checking and IPv4 or IPv6 TCP, UDP, or ICMP payload checksum checking. When this bit is reset, the COE function in the receiver is disabled and the corresponding PCE and IP HCE status bits are always cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipc {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Ipc> for bool {
    #[inline(always)]
    fn from(variant: Ipc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ipc` reader - When this bit is set, the MAC calculates the 16-bit ones complement of the ones complement sum of all received Ethernet frame payloads. It also checks whether the IPv4 Header checksum (assumed to be bytes 2526 or 2930 (VLAN-tagged) of the received Ethernet frame) is correct for the received frame and gives the status in the receive status word. The MAC also appends the 16-bit checksum calculated for the IP header datagram payload (bytes after the IPv4 header) and appends it to the Ethernet frame transferred to the application (when Type 2 COE is deselected). When this bit is reset, this function is disabled. When Type 2 COE is selected, this bit, when set, enables the IPv4 header checksum checking and IPv4 or IPv6 TCP, UDP, or ICMP payload checksum checking. When this bit is reset, the COE function in the receiver is disabled and the corresponding PCE and IP HCE status bits are always cleared."]
pub type IpcR = crate::BitReader<Ipc>;
impl IpcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ipc {
        match self.bits {
            true => Ipc::Enabled,
            false => Ipc::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ipc::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ipc::Disabled
    }
}
#[doc = "Field `ipc` writer - When this bit is set, the MAC calculates the 16-bit ones complement of the ones complement sum of all received Ethernet frame payloads. It also checks whether the IPv4 Header checksum (assumed to be bytes 2526 or 2930 (VLAN-tagged) of the received Ethernet frame) is correct for the received frame and gives the status in the receive status word. The MAC also appends the 16-bit checksum calculated for the IP header datagram payload (bytes after the IPv4 header) and appends it to the Ethernet frame transferred to the application (when Type 2 COE is deselected). When this bit is reset, this function is disabled. When Type 2 COE is selected, this bit, when set, enables the IPv4 header checksum checking and IPv4 or IPv6 TCP, UDP, or ICMP payload checksum checking. When this bit is reset, the COE function in the receiver is disabled and the corresponding PCE and IP HCE status bits are always cleared."]
pub type IpcW<'a, REG> = crate::BitWriter<'a, REG, Ipc>;
impl<'a, REG> IpcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ipc::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ipc::Disabled)
    }
}
#[doc = "When this bit is set, the MAC operates in the full-duplex mode where it can transmit and receive simultaneously.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dm {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Dm> for bool {
    #[inline(always)]
    fn from(variant: Dm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dm` reader - When this bit is set, the MAC operates in the full-duplex mode where it can transmit and receive simultaneously."]
pub type DmR = crate::BitReader<Dm>;
impl DmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dm {
        match self.bits {
            true => Dm::Enabled,
            false => Dm::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dm::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dm::Disabled
    }
}
#[doc = "Field `dm` writer - When this bit is set, the MAC operates in the full-duplex mode where it can transmit and receive simultaneously."]
pub type DmW<'a, REG> = crate::BitWriter<'a, REG, Dm>;
impl<'a, REG> DmW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dm::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dm::Disabled)
    }
}
#[doc = "When this bit is set, the MAC operates in the loopback mode at GMII or MII. The (G)MII Receive clock input is required for the loopback to work properly, because the Transmit clock is not looped-back internally.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lm {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lm> for bool {
    #[inline(always)]
    fn from(variant: Lm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lm` reader - When this bit is set, the MAC operates in the loopback mode at GMII or MII. The (G)MII Receive clock input is required for the loopback to work properly, because the Transmit clock is not looped-back internally."]
pub type LmR = crate::BitReader<Lm>;
impl LmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lm {
        match self.bits {
            false => Lm::Disabled,
            true => Lm::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lm::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lm::Enabled
    }
}
#[doc = "Field `lm` writer - When this bit is set, the MAC operates in the loopback mode at GMII or MII. The (G)MII Receive clock input is required for the loopback to work properly, because the Transmit clock is not looped-back internally."]
pub type LmW<'a, REG> = crate::BitWriter<'a, REG, Lm>;
impl<'a, REG> LmW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lm::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lm::Enabled)
    }
}
#[doc = "When this bit is set, the MAC disables the reception of frames when the gmii_txen_o is asserted in the half-duplex mode. When this bit is reset, the MAC receives all packets that are given by the PHY while transmitting. This bit is not applicable if the MAC is operating in the full-duplex mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Do {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Do> for bool {
    #[inline(always)]
    fn from(variant: Do) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `do` reader - When this bit is set, the MAC disables the reception of frames when the gmii_txen_o is asserted in the half-duplex mode. When this bit is reset, the MAC receives all packets that are given by the PHY while transmitting. This bit is not applicable if the MAC is operating in the full-duplex mode."]
pub type DoR = crate::BitReader<Do>;
impl DoR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Do {
        match self.bits {
            false => Do::Enabled,
            true => Do::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Do::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Do::Disabled
    }
}
#[doc = "Field `do` writer - When this bit is set, the MAC disables the reception of frames when the gmii_txen_o is asserted in the half-duplex mode. When this bit is reset, the MAC receives all packets that are given by the PHY while transmitting. This bit is not applicable if the MAC is operating in the full-duplex mode."]
pub type DoW<'a, REG> = crate::BitWriter<'a, REG, Do>;
impl<'a, REG> DoW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Do::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Do::Disabled)
    }
}
#[doc = "This bit selects the speed in the RMII/RGMII interface: * 0: 10 Mbps * 1: 100 Mbps This bit generates link speed encoding when TC (Bit 24) is set in the RGMII, SMII, or SGMII mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fes {
    #[doc = "0: `0`"]
    Speed10 = 0,
    #[doc = "1: `1`"]
    Speed100 = 1,
}
impl From<Fes> for bool {
    #[inline(always)]
    fn from(variant: Fes) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fes` reader - This bit selects the speed in the RMII/RGMII interface: * 0: 10 Mbps * 1: 100 Mbps This bit generates link speed encoding when TC (Bit 24) is set in the RGMII, SMII, or SGMII mode."]
pub type FesR = crate::BitReader<Fes>;
impl FesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fes {
        match self.bits {
            false => Fes::Speed10,
            true => Fes::Speed100,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_speed10(&self) -> bool {
        *self == Fes::Speed10
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_speed100(&self) -> bool {
        *self == Fes::Speed100
    }
}
#[doc = "Field `fes` writer - This bit selects the speed in the RMII/RGMII interface: * 0: 10 Mbps * 1: 100 Mbps This bit generates link speed encoding when TC (Bit 24) is set in the RGMII, SMII, or SGMII mode."]
pub type FesW<'a, REG> = crate::BitWriter<'a, REG, Fes>;
impl<'a, REG> FesW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn speed10(self) -> &'a mut crate::W<REG> {
        self.variant(Fes::Speed10)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn speed100(self) -> &'a mut crate::W<REG> {
        self.variant(Fes::Speed100)
    }
}
#[doc = "This bit selects between GMII and MII\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ps {
    #[doc = "0: `0`"]
    Gmii1000sel = 0,
    #[doc = "1: `1`"]
    Mii10100sel = 1,
}
impl From<Ps> for bool {
    #[inline(always)]
    fn from(variant: Ps) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ps` reader - This bit selects between GMII and MII"]
pub type PsR = crate::BitReader<Ps>;
impl PsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ps {
        match self.bits {
            false => Ps::Gmii1000sel,
            true => Ps::Mii10100sel,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gmii1000sel(&self) -> bool {
        *self == Ps::Gmii1000sel
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_mii10100sel(&self) -> bool {
        *self == Ps::Mii10100sel
    }
}
#[doc = "Field `ps` writer - This bit selects between GMII and MII"]
pub type PsW<'a, REG> = crate::BitWriter<'a, REG, Ps>;
impl<'a, REG> PsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn gmii1000sel(self) -> &'a mut crate::W<REG> {
        self.variant(Ps::Gmii1000sel)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn mii10100sel(self) -> &'a mut crate::W<REG> {
        self.variant(Ps::Mii10100sel)
    }
}
#[doc = "When set high, this bit makes the MAC transmitter ignore the (G)MII CRS signal during frame transmission in the half-duplex mode. This request results in no errors generated because of Loss of Carrier or No Carrier during such transmission. When this bit is low, the MAC transmitter generates such errors because of Carrier Sense and can even abort the transmissions.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dcrs {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dcrs> for bool {
    #[inline(always)]
    fn from(variant: Dcrs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dcrs` reader - When set high, this bit makes the MAC transmitter ignore the (G)MII CRS signal during frame transmission in the half-duplex mode. This request results in no errors generated because of Loss of Carrier or No Carrier during such transmission. When this bit is low, the MAC transmitter generates such errors because of Carrier Sense and can even abort the transmissions."]
pub type DcrsR = crate::BitReader<Dcrs>;
impl DcrsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dcrs {
        match self.bits {
            false => Dcrs::Disabled,
            true => Dcrs::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dcrs::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dcrs::Enabled
    }
}
#[doc = "Field `dcrs` writer - When set high, this bit makes the MAC transmitter ignore the (G)MII CRS signal during frame transmission in the half-duplex mode. This request results in no errors generated because of Loss of Carrier or No Carrier during such transmission. When this bit is low, the MAC transmitter generates such errors because of Carrier Sense and can even abort the transmissions."]
pub type DcrsW<'a, REG> = crate::BitWriter<'a, REG, Dcrs>;
impl<'a, REG> DcrsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dcrs::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dcrs::Enabled)
    }
}
#[doc = "These bits control the minimum IFG between frames during transmission. In the half-duplex mode, the minimum IFG can be configured only for 64 bit times (IFG = 100). Lower values are not considered. In the 1000-Mbps mode, the minimum IFG supported is 80 bit times (and above).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ifg {
    #[doc = "0: `0`"]
    Ifg96bittimes = 0,
    #[doc = "1: `1`"]
    Ifg88bittimes = 1,
    #[doc = "2: `10`"]
    Ifg80bittimes = 2,
    #[doc = "3: `11`"]
    Ifg72bittimes = 3,
    #[doc = "4: `100`"]
    Ifg64bittimes = 4,
    #[doc = "5: `101`"]
    Ifg56bittimes = 5,
    #[doc = "6: `110`"]
    Ifg48bittimes = 6,
    #[doc = "7: `111`"]
    Ifg40bittimes = 7,
}
impl From<Ifg> for u8 {
    #[inline(always)]
    fn from(variant: Ifg) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ifg {
    type Ux = u8;
}
#[doc = "Field `ifg` reader - These bits control the minimum IFG between frames during transmission. In the half-duplex mode, the minimum IFG can be configured only for 64 bit times (IFG = 100). Lower values are not considered. In the 1000-Mbps mode, the minimum IFG supported is 80 bit times (and above)."]
pub type IfgR = crate::FieldReader<Ifg>;
impl IfgR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ifg {
        match self.bits {
            0 => Ifg::Ifg96bittimes,
            1 => Ifg::Ifg88bittimes,
            2 => Ifg::Ifg80bittimes,
            3 => Ifg::Ifg72bittimes,
            4 => Ifg::Ifg64bittimes,
            5 => Ifg::Ifg56bittimes,
            6 => Ifg::Ifg48bittimes,
            7 => Ifg::Ifg40bittimes,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ifg96bittimes(&self) -> bool {
        *self == Ifg::Ifg96bittimes
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ifg88bittimes(&self) -> bool {
        *self == Ifg::Ifg88bittimes
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_ifg80bittimes(&self) -> bool {
        *self == Ifg::Ifg80bittimes
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_ifg72bittimes(&self) -> bool {
        *self == Ifg::Ifg72bittimes
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_ifg64bittimes(&self) -> bool {
        *self == Ifg::Ifg64bittimes
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_ifg56bittimes(&self) -> bool {
        *self == Ifg::Ifg56bittimes
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_ifg48bittimes(&self) -> bool {
        *self == Ifg::Ifg48bittimes
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_ifg40bittimes(&self) -> bool {
        *self == Ifg::Ifg40bittimes
    }
}
#[doc = "Field `ifg` writer - These bits control the minimum IFG between frames during transmission. In the half-duplex mode, the minimum IFG can be configured only for 64 bit times (IFG = 100). Lower values are not considered. In the 1000-Mbps mode, the minimum IFG supported is 80 bit times (and above)."]
pub type IfgW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Ifg>;
impl<'a, REG> IfgW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ifg96bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg96bittimes)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ifg88bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg88bittimes)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn ifg80bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg80bittimes)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn ifg72bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg72bittimes)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn ifg64bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg64bittimes)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn ifg56bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg56bittimes)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn ifg48bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg48bittimes)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn ifg40bittimes(self) -> &'a mut crate::W<REG> {
        self.variant(Ifg::Ifg40bittimes)
    }
}
#[doc = "When this bit is set, the MAC allows Jumbo frames of 9,018 bytes (9,022 bytes for VLAN tagged frames) without reporting a giant frame error in the receive frame status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Je {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Je> for bool {
    #[inline(always)]
    fn from(variant: Je) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `je` reader - When this bit is set, the MAC allows Jumbo frames of 9,018 bytes (9,022 bytes for VLAN tagged frames) without reporting a giant frame error in the receive frame status."]
pub type JeR = crate::BitReader<Je>;
impl JeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Je {
        match self.bits {
            false => Je::Disabled,
            true => Je::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Je::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Je::Enabled
    }
}
#[doc = "Field `je` writer - When this bit is set, the MAC allows Jumbo frames of 9,018 bytes (9,022 bytes for VLAN tagged frames) without reporting a giant frame error in the receive frame status."]
pub type JeW<'a, REG> = crate::BitWriter<'a, REG, Je>;
impl<'a, REG> JeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Je::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Je::Enabled)
    }
}
#[doc = "When this bit is set, the MAC allows frame bursting during transmission in the GMII half-duplex mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Be {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Be> for bool {
    #[inline(always)]
    fn from(variant: Be) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `be` reader - When this bit is set, the MAC allows frame bursting during transmission in the GMII half-duplex mode."]
pub type BeR = crate::BitReader<Be>;
impl BeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Be {
        match self.bits {
            false => Be::Disabled,
            true => Be::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Be::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Be::Enabled
    }
}
#[doc = "Field `be` writer - When this bit is set, the MAC allows frame bursting during transmission in the GMII half-duplex mode."]
pub type BeW<'a, REG> = crate::BitWriter<'a, REG, Be>;
impl<'a, REG> BeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Be::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Be::Enabled)
    }
}
#[doc = "When this bit is set, the MAC disables the jabber timer on the transmitter. The MAC can transfer frames of up to 16,384 bytes. When this bit is reset, the MAC cuts off the transmitter if the application sends out more than 2,048 bytes of data (10,240 if JE is set high) during transmission.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Jd {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Jd> for bool {
    #[inline(always)]
    fn from(variant: Jd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `jd` reader - When this bit is set, the MAC disables the jabber timer on the transmitter. The MAC can transfer frames of up to 16,384 bytes. When this bit is reset, the MAC cuts off the transmitter if the application sends out more than 2,048 bytes of data (10,240 if JE is set high) during transmission."]
pub type JdR = crate::BitReader<Jd>;
impl JdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Jd {
        match self.bits {
            false => Jd::Enabled,
            true => Jd::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Jd::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Jd::Disabled
    }
}
#[doc = "Field `jd` writer - When this bit is set, the MAC disables the jabber timer on the transmitter. The MAC can transfer frames of up to 16,384 bytes. When this bit is reset, the MAC cuts off the transmitter if the application sends out more than 2,048 bytes of data (10,240 if JE is set high) during transmission."]
pub type JdW<'a, REG> = crate::BitWriter<'a, REG, Jd>;
impl<'a, REG> JdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Jd::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Jd::Disabled)
    }
}
#[doc = "When this bit is set, the MAC disables the watchdog timer on the receiver. The MAC can receive frames of up to 16,384 bytes. When this bit is reset, the MAC does not allow more than 2,048 bytes (10,240 if JE is set high) of the frame being received. The MAC cuts off any bytes received after 2,048 bytes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wd {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Wd> for bool {
    #[inline(always)]
    fn from(variant: Wd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wd` reader - When this bit is set, the MAC disables the watchdog timer on the receiver. The MAC can receive frames of up to 16,384 bytes. When this bit is reset, the MAC does not allow more than 2,048 bytes (10,240 if JE is set high) of the frame being received. The MAC cuts off any bytes received after 2,048 bytes."]
pub type WdR = crate::BitReader<Wd>;
impl WdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wd {
        match self.bits {
            false => Wd::Enabled,
            true => Wd::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Wd::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Wd::Disabled
    }
}
#[doc = "Field `wd` writer - When this bit is set, the MAC disables the watchdog timer on the receiver. The MAC can receive frames of up to 16,384 bytes. When this bit is reset, the MAC does not allow more than 2,048 bytes (10,240 if JE is set high) of the frame being received. The MAC cuts off any bytes received after 2,048 bytes."]
pub type WdW<'a, REG> = crate::BitWriter<'a, REG, Wd>;
impl<'a, REG> WdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Wd::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Wd::Disabled)
    }
}
#[doc = "When set, this bit enables the transmission of duplex mode, link speed, and link up or down information to the PHY in the RGMII. When this bit is reset, no such information is driven to the PHY.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tc {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Tc> for bool {
    #[inline(always)]
    fn from(variant: Tc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tc` reader - When set, this bit enables the transmission of duplex mode, link speed, and link up or down information to the PHY in the RGMII. When this bit is reset, no such information is driven to the PHY."]
pub type TcR = crate::BitReader<Tc>;
impl TcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tc {
        match self.bits {
            true => Tc::Enabled,
            false => Tc::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tc::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tc::Disabled
    }
}
#[doc = "Field `tc` writer - When set, this bit enables the transmission of duplex mode, link speed, and link up or down information to the PHY in the RGMII. When this bit is reset, no such information is driven to the PHY."]
pub type TcW<'a, REG> = crate::BitWriter<'a, REG, Tc>;
impl<'a, REG> TcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tc::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tc::Disabled)
    }
}
#[doc = "When set, the last 4 bytes (FCS) of all frames of Ether type (type field greater than 0x0600) are stripped and dropped before forwarding the frame to the application. This function is not valid when the IP Checksum Engine (Type 1) is enabled in the MAC receiver.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cst {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Cst> for bool {
    #[inline(always)]
    fn from(variant: Cst) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cst` reader - When set, the last 4 bytes (FCS) of all frames of Ether type (type field greater than 0x0600) are stripped and dropped before forwarding the frame to the application. This function is not valid when the IP Checksum Engine (Type 1) is enabled in the MAC receiver."]
pub type CstR = crate::BitReader<Cst>;
impl CstR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cst {
        match self.bits {
            false => Cst::Disabled,
            true => Cst::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Cst::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Cst::Enabled
    }
}
#[doc = "Field `cst` writer - When set, the last 4 bytes (FCS) of all frames of Ether type (type field greater than 0x0600) are stripped and dropped before forwarding the frame to the application. This function is not valid when the IP Checksum Engine (Type 1) is enabled in the MAC receiver."]
pub type CstW<'a, REG> = crate::BitWriter<'a, REG, Cst>;
impl<'a, REG> CstW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cst::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cst::Enabled)
    }
}
#[doc = "Field `twokpe` reader - When set, the MAC considers all frames, with up to 2,000 bytes length, as normal packets. When Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 2K bytes as Giant frames. When this bit is reset and Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 1,518 bytes (1,522 bytes for tagged) as Giant frames. When Bit 20 (Jumbo Enable) is set, setting this bit has no effect on Giant Frame status."]
pub type TwokpeR = crate::BitReader;
#[doc = "Field `twokpe` writer - When set, the MAC considers all frames, with up to 2,000 bytes length, as normal packets. When Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 2K bytes as Giant frames. When this bit is reset and Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 1,518 bytes (1,522 bytes for tagged) as Giant frames. When Bit 20 (Jumbo Enable) is set, setting this bit has no effect on Giant Frame status."]
pub type TwokpeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - These bits control the number of preamble bytes that are added to the beginning of every Transmit frame. The preamble reduction occurs only when the MAC is operating"]
    #[inline(always)]
    pub fn prelen(&self) -> PrelenR {
        PrelenR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - When this bit is set, the receiver state machine of the MAC is enabled for receiving frames from the GMII or MII. When this bit is reset, the MAC receive state machine is disabled after the completion of the reception of the current frame, and does not receive any further frames from the GMII or MII."]
    #[inline(always)]
    pub fn re(&self) -> ReR {
        ReR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When this bit is set, the transmit state machine of the MAC is enabled for transmission on the GMII or MII. When this bit is reset, the MAC transmit state machine is disabled after the completion of the transmission of the current frame, and does not transmit any further frames."]
    #[inline(always)]
    pub fn te(&self) -> TeR {
        TeR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When this bit is set, the deferral check function is enabled in the MAC. The MAC issues a Frame Abort status, along with the excessive deferral error bit set in the transmit frame status, when the transmit state machine is deferred for more than 24,288 bit times in the 10 or 100 Mbps mode. If the MAC is configured for 1000 Mbps operation, or if the Jumbo frame mode is enabled in the 10 or 100 Mbps mode, the threshold for deferral is 155,680 bits times. Deferral begins when the transmitter is ready to transmit, but is prevented because of an active carrier sense signal (CRS) on GMII or MII. Defer time is not cumulative. When the transmitter defers for 10,000 bit times, it transmits, collides, backs off, and then defers again after completion of back-off. The deferral timer resets to 0 and restarts. When this bit is reset, the deferral check function is disabled and the MAC defers until the CRS signal goes inactive. This bit is applicable only in the half-duplex mode."]
    #[inline(always)]
    pub fn dc(&self) -> DcR {
        DcR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:6 - The Back-Off limit determines the random integer number (r) of slot time delays (4,096 bit times for 1000 Mbps and 512 bit times for 10/100 Mbps) for which the MAC waits before rescheduling a transmission attempt during retries after a collision. This bit is applicable only in the half-duplex mode. * 00: k = min (n, 10) * 01: k = min (n, 8) * 10: k = min (n, 4) * 11: k = min (n, 1) where &lt;i> n &lt;/i>= retransmission attempt. The random integer &lt;i> r &lt;/i> takes the value in the range 0 &lt;= r &lt; kth power of 2"]
    #[inline(always)]
    pub fn bl(&self) -> BlR {
        BlR::new(((self.bits >> 5) & 3) as u8)
    }
    #[doc = "Bit 7 - When this bit is set, the MAC strips the Pad or FCS field on the incoming frames only if the value of the length field is less than 1,536 bytes. All received frames with length field greater than or equal to 1,536 bytes are passed to the application without stripping the Pad or FCS field. When this bit is reset, the MAC passes all incoming frames, without modifying them, to the Host."]
    #[inline(always)]
    pub fn acs(&self) -> AcsR {
        AcsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit indicates whether the link is up or down during the transmission of configuration in the RGMII, SGMII, or SMII interface"]
    #[inline(always)]
    pub fn lud(&self) -> LudR {
        LudR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - When this bit is set, the MAC attempts only one transmission. When a collision occurs on the GMII or MII interface, the MAC ignores the current frame transmission and reports a Frame Abort with excessive collision error in the transmit frame status. When this bit is reset, the MAC attempts retries based on the settings of the BL field (Bits \\[6:5\\]). This bit is applicable only in the half-duplex mode."]
    #[inline(always)]
    pub fn dr(&self) -> DrR {
        DrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - When this bit is set, the MAC calculates the 16-bit ones complement of the ones complement sum of all received Ethernet frame payloads. It also checks whether the IPv4 Header checksum (assumed to be bytes 2526 or 2930 (VLAN-tagged) of the received Ethernet frame) is correct for the received frame and gives the status in the receive status word. The MAC also appends the 16-bit checksum calculated for the IP header datagram payload (bytes after the IPv4 header) and appends it to the Ethernet frame transferred to the application (when Type 2 COE is deselected). When this bit is reset, this function is disabled. When Type 2 COE is selected, this bit, when set, enables the IPv4 header checksum checking and IPv4 or IPv6 TCP, UDP, or ICMP payload checksum checking. When this bit is reset, the COE function in the receiver is disabled and the corresponding PCE and IP HCE status bits are always cleared."]
    #[inline(always)]
    pub fn ipc(&self) -> IpcR {
        IpcR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - When this bit is set, the MAC operates in the full-duplex mode where it can transmit and receive simultaneously."]
    #[inline(always)]
    pub fn dm(&self) -> DmR {
        DmR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - When this bit is set, the MAC operates in the loopback mode at GMII or MII. The (G)MII Receive clock input is required for the loopback to work properly, because the Transmit clock is not looped-back internally."]
    #[inline(always)]
    pub fn lm(&self) -> LmR {
        LmR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - When this bit is set, the MAC disables the reception of frames when the gmii_txen_o is asserted in the half-duplex mode. When this bit is reset, the MAC receives all packets that are given by the PHY while transmitting. This bit is not applicable if the MAC is operating in the full-duplex mode."]
    #[inline(always)]
    pub fn do_(&self) -> DoR {
        DoR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - This bit selects the speed in the RMII/RGMII interface: * 0: 10 Mbps * 1: 100 Mbps This bit generates link speed encoding when TC (Bit 24) is set in the RGMII, SMII, or SGMII mode."]
    #[inline(always)]
    pub fn fes(&self) -> FesR {
        FesR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - This bit selects between GMII and MII"]
    #[inline(always)]
    pub fn ps(&self) -> PsR {
        PsR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - When set high, this bit makes the MAC transmitter ignore the (G)MII CRS signal during frame transmission in the half-duplex mode. This request results in no errors generated because of Loss of Carrier or No Carrier during such transmission. When this bit is low, the MAC transmitter generates such errors because of Carrier Sense and can even abort the transmissions."]
    #[inline(always)]
    pub fn dcrs(&self) -> DcrsR {
        DcrsR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:19 - These bits control the minimum IFG between frames during transmission. In the half-duplex mode, the minimum IFG can be configured only for 64 bit times (IFG = 100). Lower values are not considered. In the 1000-Mbps mode, the minimum IFG supported is 80 bit times (and above)."]
    #[inline(always)]
    pub fn ifg(&self) -> IfgR {
        IfgR::new(((self.bits >> 17) & 7) as u8)
    }
    #[doc = "Bit 20 - When this bit is set, the MAC allows Jumbo frames of 9,018 bytes (9,022 bytes for VLAN tagged frames) without reporting a giant frame error in the receive frame status."]
    #[inline(always)]
    pub fn je(&self) -> JeR {
        JeR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - When this bit is set, the MAC allows frame bursting during transmission in the GMII half-duplex mode."]
    #[inline(always)]
    pub fn be(&self) -> BeR {
        BeR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - When this bit is set, the MAC disables the jabber timer on the transmitter. The MAC can transfer frames of up to 16,384 bytes. When this bit is reset, the MAC cuts off the transmitter if the application sends out more than 2,048 bytes of data (10,240 if JE is set high) during transmission."]
    #[inline(always)]
    pub fn jd(&self) -> JdR {
        JdR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - When this bit is set, the MAC disables the watchdog timer on the receiver. The MAC can receive frames of up to 16,384 bytes. When this bit is reset, the MAC does not allow more than 2,048 bytes (10,240 if JE is set high) of the frame being received. The MAC cuts off any bytes received after 2,048 bytes."]
    #[inline(always)]
    pub fn wd(&self) -> WdR {
        WdR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - When set, this bit enables the transmission of duplex mode, link speed, and link up or down information to the PHY in the RGMII. When this bit is reset, no such information is driven to the PHY."]
    #[inline(always)]
    pub fn tc(&self) -> TcR {
        TcR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - When set, the last 4 bytes (FCS) of all frames of Ether type (type field greater than 0x0600) are stripped and dropped before forwarding the frame to the application. This function is not valid when the IP Checksum Engine (Type 1) is enabled in the MAC receiver."]
    #[inline(always)]
    pub fn cst(&self) -> CstR {
        CstR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 27 - When set, the MAC considers all frames, with up to 2,000 bytes length, as normal packets. When Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 2K bytes as Giant frames. When this bit is reset and Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 1,518 bytes (1,522 bytes for tagged) as Giant frames. When Bit 20 (Jumbo Enable) is set, setting this bit has no effect on Giant Frame status."]
    #[inline(always)]
    pub fn twokpe(&self) -> TwokpeR {
        TwokpeR::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - These bits control the number of preamble bytes that are added to the beginning of every Transmit frame. The preamble reduction occurs only when the MAC is operating"]
    #[inline(always)]
    #[must_use]
    pub fn prelen(&mut self) -> PrelenW<GmacgrpMacConfigurationSpec> {
        PrelenW::new(self, 0)
    }
    #[doc = "Bit 2 - When this bit is set, the receiver state machine of the MAC is enabled for receiving frames from the GMII or MII. When this bit is reset, the MAC receive state machine is disabled after the completion of the reception of the current frame, and does not receive any further frames from the GMII or MII."]
    #[inline(always)]
    #[must_use]
    pub fn re(&mut self) -> ReW<GmacgrpMacConfigurationSpec> {
        ReW::new(self, 2)
    }
    #[doc = "Bit 3 - When this bit is set, the transmit state machine of the MAC is enabled for transmission on the GMII or MII. When this bit is reset, the MAC transmit state machine is disabled after the completion of the transmission of the current frame, and does not transmit any further frames."]
    #[inline(always)]
    #[must_use]
    pub fn te(&mut self) -> TeW<GmacgrpMacConfigurationSpec> {
        TeW::new(self, 3)
    }
    #[doc = "Bit 4 - When this bit is set, the deferral check function is enabled in the MAC. The MAC issues a Frame Abort status, along with the excessive deferral error bit set in the transmit frame status, when the transmit state machine is deferred for more than 24,288 bit times in the 10 or 100 Mbps mode. If the MAC is configured for 1000 Mbps operation, or if the Jumbo frame mode is enabled in the 10 or 100 Mbps mode, the threshold for deferral is 155,680 bits times. Deferral begins when the transmitter is ready to transmit, but is prevented because of an active carrier sense signal (CRS) on GMII or MII. Defer time is not cumulative. When the transmitter defers for 10,000 bit times, it transmits, collides, backs off, and then defers again after completion of back-off. The deferral timer resets to 0 and restarts. When this bit is reset, the deferral check function is disabled and the MAC defers until the CRS signal goes inactive. This bit is applicable only in the half-duplex mode."]
    #[inline(always)]
    #[must_use]
    pub fn dc(&mut self) -> DcW<GmacgrpMacConfigurationSpec> {
        DcW::new(self, 4)
    }
    #[doc = "Bits 5:6 - The Back-Off limit determines the random integer number (r) of slot time delays (4,096 bit times for 1000 Mbps and 512 bit times for 10/100 Mbps) for which the MAC waits before rescheduling a transmission attempt during retries after a collision. This bit is applicable only in the half-duplex mode. * 00: k = min (n, 10) * 01: k = min (n, 8) * 10: k = min (n, 4) * 11: k = min (n, 1) where &lt;i> n &lt;/i>= retransmission attempt. The random integer &lt;i> r &lt;/i> takes the value in the range 0 &lt;= r &lt; kth power of 2"]
    #[inline(always)]
    #[must_use]
    pub fn bl(&mut self) -> BlW<GmacgrpMacConfigurationSpec> {
        BlW::new(self, 5)
    }
    #[doc = "Bit 7 - When this bit is set, the MAC strips the Pad or FCS field on the incoming frames only if the value of the length field is less than 1,536 bytes. All received frames with length field greater than or equal to 1,536 bytes are passed to the application without stripping the Pad or FCS field. When this bit is reset, the MAC passes all incoming frames, without modifying them, to the Host."]
    #[inline(always)]
    #[must_use]
    pub fn acs(&mut self) -> AcsW<GmacgrpMacConfigurationSpec> {
        AcsW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit indicates whether the link is up or down during the transmission of configuration in the RGMII, SGMII, or SMII interface"]
    #[inline(always)]
    #[must_use]
    pub fn lud(&mut self) -> LudW<GmacgrpMacConfigurationSpec> {
        LudW::new(self, 8)
    }
    #[doc = "Bit 9 - When this bit is set, the MAC attempts only one transmission. When a collision occurs on the GMII or MII interface, the MAC ignores the current frame transmission and reports a Frame Abort with excessive collision error in the transmit frame status. When this bit is reset, the MAC attempts retries based on the settings of the BL field (Bits \\[6:5\\]). This bit is applicable only in the half-duplex mode."]
    #[inline(always)]
    #[must_use]
    pub fn dr(&mut self) -> DrW<GmacgrpMacConfigurationSpec> {
        DrW::new(self, 9)
    }
    #[doc = "Bit 10 - When this bit is set, the MAC calculates the 16-bit ones complement of the ones complement sum of all received Ethernet frame payloads. It also checks whether the IPv4 Header checksum (assumed to be bytes 2526 or 2930 (VLAN-tagged) of the received Ethernet frame) is correct for the received frame and gives the status in the receive status word. The MAC also appends the 16-bit checksum calculated for the IP header datagram payload (bytes after the IPv4 header) and appends it to the Ethernet frame transferred to the application (when Type 2 COE is deselected). When this bit is reset, this function is disabled. When Type 2 COE is selected, this bit, when set, enables the IPv4 header checksum checking and IPv4 or IPv6 TCP, UDP, or ICMP payload checksum checking. When this bit is reset, the COE function in the receiver is disabled and the corresponding PCE and IP HCE status bits are always cleared."]
    #[inline(always)]
    #[must_use]
    pub fn ipc(&mut self) -> IpcW<GmacgrpMacConfigurationSpec> {
        IpcW::new(self, 10)
    }
    #[doc = "Bit 11 - When this bit is set, the MAC operates in the full-duplex mode where it can transmit and receive simultaneously."]
    #[inline(always)]
    #[must_use]
    pub fn dm(&mut self) -> DmW<GmacgrpMacConfigurationSpec> {
        DmW::new(self, 11)
    }
    #[doc = "Bit 12 - When this bit is set, the MAC operates in the loopback mode at GMII or MII. The (G)MII Receive clock input is required for the loopback to work properly, because the Transmit clock is not looped-back internally."]
    #[inline(always)]
    #[must_use]
    pub fn lm(&mut self) -> LmW<GmacgrpMacConfigurationSpec> {
        LmW::new(self, 12)
    }
    #[doc = "Bit 13 - When this bit is set, the MAC disables the reception of frames when the gmii_txen_o is asserted in the half-duplex mode. When this bit is reset, the MAC receives all packets that are given by the PHY while transmitting. This bit is not applicable if the MAC is operating in the full-duplex mode."]
    #[inline(always)]
    #[must_use]
    pub fn do_(&mut self) -> DoW<GmacgrpMacConfigurationSpec> {
        DoW::new(self, 13)
    }
    #[doc = "Bit 14 - This bit selects the speed in the RMII/RGMII interface: * 0: 10 Mbps * 1: 100 Mbps This bit generates link speed encoding when TC (Bit 24) is set in the RGMII, SMII, or SGMII mode."]
    #[inline(always)]
    #[must_use]
    pub fn fes(&mut self) -> FesW<GmacgrpMacConfigurationSpec> {
        FesW::new(self, 14)
    }
    #[doc = "Bit 15 - This bit selects between GMII and MII"]
    #[inline(always)]
    #[must_use]
    pub fn ps(&mut self) -> PsW<GmacgrpMacConfigurationSpec> {
        PsW::new(self, 15)
    }
    #[doc = "Bit 16 - When set high, this bit makes the MAC transmitter ignore the (G)MII CRS signal during frame transmission in the half-duplex mode. This request results in no errors generated because of Loss of Carrier or No Carrier during such transmission. When this bit is low, the MAC transmitter generates such errors because of Carrier Sense and can even abort the transmissions."]
    #[inline(always)]
    #[must_use]
    pub fn dcrs(&mut self) -> DcrsW<GmacgrpMacConfigurationSpec> {
        DcrsW::new(self, 16)
    }
    #[doc = "Bits 17:19 - These bits control the minimum IFG between frames during transmission. In the half-duplex mode, the minimum IFG can be configured only for 64 bit times (IFG = 100). Lower values are not considered. In the 1000-Mbps mode, the minimum IFG supported is 80 bit times (and above)."]
    #[inline(always)]
    #[must_use]
    pub fn ifg(&mut self) -> IfgW<GmacgrpMacConfigurationSpec> {
        IfgW::new(self, 17)
    }
    #[doc = "Bit 20 - When this bit is set, the MAC allows Jumbo frames of 9,018 bytes (9,022 bytes for VLAN tagged frames) without reporting a giant frame error in the receive frame status."]
    #[inline(always)]
    #[must_use]
    pub fn je(&mut self) -> JeW<GmacgrpMacConfigurationSpec> {
        JeW::new(self, 20)
    }
    #[doc = "Bit 21 - When this bit is set, the MAC allows frame bursting during transmission in the GMII half-duplex mode."]
    #[inline(always)]
    #[must_use]
    pub fn be(&mut self) -> BeW<GmacgrpMacConfigurationSpec> {
        BeW::new(self, 21)
    }
    #[doc = "Bit 22 - When this bit is set, the MAC disables the jabber timer on the transmitter. The MAC can transfer frames of up to 16,384 bytes. When this bit is reset, the MAC cuts off the transmitter if the application sends out more than 2,048 bytes of data (10,240 if JE is set high) during transmission."]
    #[inline(always)]
    #[must_use]
    pub fn jd(&mut self) -> JdW<GmacgrpMacConfigurationSpec> {
        JdW::new(self, 22)
    }
    #[doc = "Bit 23 - When this bit is set, the MAC disables the watchdog timer on the receiver. The MAC can receive frames of up to 16,384 bytes. When this bit is reset, the MAC does not allow more than 2,048 bytes (10,240 if JE is set high) of the frame being received. The MAC cuts off any bytes received after 2,048 bytes."]
    #[inline(always)]
    #[must_use]
    pub fn wd(&mut self) -> WdW<GmacgrpMacConfigurationSpec> {
        WdW::new(self, 23)
    }
    #[doc = "Bit 24 - When set, this bit enables the transmission of duplex mode, link speed, and link up or down information to the PHY in the RGMII. When this bit is reset, no such information is driven to the PHY."]
    #[inline(always)]
    #[must_use]
    pub fn tc(&mut self) -> TcW<GmacgrpMacConfigurationSpec> {
        TcW::new(self, 24)
    }
    #[doc = "Bit 25 - When set, the last 4 bytes (FCS) of all frames of Ether type (type field greater than 0x0600) are stripped and dropped before forwarding the frame to the application. This function is not valid when the IP Checksum Engine (Type 1) is enabled in the MAC receiver."]
    #[inline(always)]
    #[must_use]
    pub fn cst(&mut self) -> CstW<GmacgrpMacConfigurationSpec> {
        CstW::new(self, 25)
    }
    #[doc = "Bit 27 - When set, the MAC considers all frames, with up to 2,000 bytes length, as normal packets. When Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 2K bytes as Giant frames. When this bit is reset and Bit 20 (Jumbo Enable) is not set, the MAC considers all received frames of size more than 1,518 bytes (1,522 bytes for tagged) as Giant frames. When Bit 20 (Jumbo Enable) is set, setting this bit has no effect on Giant Frame status."]
    #[inline(always)]
    #[must_use]
    pub fn twokpe(&mut self) -> TwokpeW<GmacgrpMacConfigurationSpec> {
        TwokpeW::new(self, 27)
    }
}
#[doc = "The MAC Configuration register establishes receive and transmit operating modes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_configuration::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_configuration::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMacConfigurationSpec;
impl crate::RegisterSpec for GmacgrpMacConfigurationSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`gmacgrp_mac_configuration::R`](R) reader structure"]
impl crate::Readable for GmacgrpMacConfigurationSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mac_configuration::W`](W) writer structure"]
impl crate::Writable for GmacgrpMacConfigurationSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MAC_Configuration to value 0"]
impl crate::Resettable for GmacgrpMacConfigurationSpec {
    const RESET_VALUE: u32 = 0;
}
