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
#[doc = "Register `devgrp_dctl` reader"]
pub type R = crate::R<DevgrpDctlSpec>;
#[doc = "Register `devgrp_dctl` writer"]
pub type W = crate::W<DevgrpDctlSpec>;
#[doc = "When the application sets this bit, the core initiates remote signaling to wake up the USB host. The application must Set this bit to instruct the core to exit the Suspend state. As specified in the USB 2.0 specification, the application must clear this bit 115 ms after setting it. Remote Wakeup Signaling (RmtWkUpSig) When LPM is enabled, In L1 state the behavior of this bit is as follows: When the application sets this bit, the core initiates L1 remote signaling to wake up the USB host. The application must set this bit to instruct the core to exit the Sleep state. As specified in the LPM specification, the hardware will automatically clear this bit after a time of 50us (TL1DevDrvResume) after set by application. Application should not set this bit when GLPMCFG bRemoteWake from the previous LPM transaction was zero.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rmtwkupsig {
    #[doc = "0: `0`"]
    Noexit = 0,
    #[doc = "1: `1`"]
    Exit = 1,
}
impl From<Rmtwkupsig> for bool {
    #[inline(always)]
    fn from(variant: Rmtwkupsig) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rmtwkupsig` reader - When the application sets this bit, the core initiates remote signaling to wake up the USB host. The application must Set this bit to instruct the core to exit the Suspend state. As specified in the USB 2.0 specification, the application must clear this bit 115 ms after setting it. Remote Wakeup Signaling (RmtWkUpSig) When LPM is enabled, In L1 state the behavior of this bit is as follows: When the application sets this bit, the core initiates L1 remote signaling to wake up the USB host. The application must set this bit to instruct the core to exit the Sleep state. As specified in the LPM specification, the hardware will automatically clear this bit after a time of 50us (TL1DevDrvResume) after set by application. Application should not set this bit when GLPMCFG bRemoteWake from the previous LPM transaction was zero."]
pub type RmtwkupsigR = crate::BitReader<Rmtwkupsig>;
impl RmtwkupsigR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rmtwkupsig {
        match self.bits {
            false => Rmtwkupsig::Noexit,
            true => Rmtwkupsig::Exit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noexit(&self) -> bool {
        *self == Rmtwkupsig::Noexit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_exit(&self) -> bool {
        *self == Rmtwkupsig::Exit
    }
}
#[doc = "Field `rmtwkupsig` writer - When the application sets this bit, the core initiates remote signaling to wake up the USB host. The application must Set this bit to instruct the core to exit the Suspend state. As specified in the USB 2.0 specification, the application must clear this bit 115 ms after setting it. Remote Wakeup Signaling (RmtWkUpSig) When LPM is enabled, In L1 state the behavior of this bit is as follows: When the application sets this bit, the core initiates L1 remote signaling to wake up the USB host. The application must set this bit to instruct the core to exit the Sleep state. As specified in the LPM specification, the hardware will automatically clear this bit after a time of 50us (TL1DevDrvResume) after set by application. Application should not set this bit when GLPMCFG bRemoteWake from the previous LPM transaction was zero."]
pub type RmtwkupsigW<'a, REG> = crate::BitWriter<'a, REG, Rmtwkupsig>;
impl<'a, REG> RmtwkupsigW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noexit(self) -> &'a mut crate::W<REG> {
        self.variant(Rmtwkupsig::Noexit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn exit(self) -> &'a mut crate::W<REG> {
        self.variant(Rmtwkupsig::Exit)
    }
}
#[doc = "The application uses this bit to signal the otg core to do a soft disconnect. As long as this bit is Set, the host does not see that the device is connected, and the device does not receive signals on the USB. The core stays in the disconnected state until the application clears this bit. There is a minimum duration for which the core must keep this bit set. When this bit is cleared after a soft disconnect, the core drives the phy_opmode_o signal on the ULPI, which generates a device connect event to the USB host. When the device is reconnected, the USB host restarts device enumeration.;\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sftdiscon {
    #[doc = "0: `0`"]
    Nodisconnect = 0,
    #[doc = "1: `1`"]
    Disconnect = 1,
}
impl From<Sftdiscon> for bool {
    #[inline(always)]
    fn from(variant: Sftdiscon) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sftdiscon` reader - The application uses this bit to signal the otg core to do a soft disconnect. As long as this bit is Set, the host does not see that the device is connected, and the device does not receive signals on the USB. The core stays in the disconnected state until the application clears this bit. There is a minimum duration for which the core must keep this bit set. When this bit is cleared after a soft disconnect, the core drives the phy_opmode_o signal on the ULPI, which generates a device connect event to the USB host. When the device is reconnected, the USB host restarts device enumeration.;"]
pub type SftdisconR = crate::BitReader<Sftdiscon>;
impl SftdisconR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sftdiscon {
        match self.bits {
            false => Sftdiscon::Nodisconnect,
            true => Sftdiscon::Disconnect,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nodisconnect(&self) -> bool {
        *self == Sftdiscon::Nodisconnect
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disconnect(&self) -> bool {
        *self == Sftdiscon::Disconnect
    }
}
#[doc = "Field `sftdiscon` writer - The application uses this bit to signal the otg core to do a soft disconnect. As long as this bit is Set, the host does not see that the device is connected, and the device does not receive signals on the USB. The core stays in the disconnected state until the application clears this bit. There is a minimum duration for which the core must keep this bit set. When this bit is cleared after a soft disconnect, the core drives the phy_opmode_o signal on the ULPI, which generates a device connect event to the USB host. When the device is reconnected, the USB host restarts device enumeration.;"]
pub type SftdisconW<'a, REG> = crate::BitWriter<'a, REG, Sftdiscon>;
impl<'a, REG> SftdisconW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nodisconnect(self) -> &'a mut crate::W<REG> {
        self.variant(Sftdiscon::Nodisconnect)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disconnect(self) -> &'a mut crate::W<REG> {
        self.variant(Sftdiscon::Disconnect)
    }
}
#[doc = "Defines IN NAK conditions.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gnpinnaksts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Gnpinnaksts> for bool {
    #[inline(always)]
    fn from(variant: Gnpinnaksts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gnpinnaksts` reader - Defines IN NAK conditions."]
pub type GnpinnakstsR = crate::BitReader<Gnpinnaksts>;
impl GnpinnakstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gnpinnaksts {
        match self.bits {
            false => Gnpinnaksts::Inactive,
            true => Gnpinnaksts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Gnpinnaksts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Gnpinnaksts::Active
    }
}
#[doc = "Field `gnpinnaksts` writer - Defines IN NAK conditions."]
pub type GnpinnakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Reports NAK status. All isochronous OUT packets aredropped.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Goutnaksts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Goutnaksts> for bool {
    #[inline(always)]
    fn from(variant: Goutnaksts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `goutnaksts` reader - Reports NAK status. All isochronous OUT packets aredropped."]
pub type GoutnakstsR = crate::BitReader<Goutnaksts>;
impl GoutnakstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Goutnaksts {
        match self.bits {
            false => Goutnaksts::Inactive,
            true => Goutnaksts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Goutnaksts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Goutnaksts::Active
    }
}
#[doc = "Field `goutnaksts` writer - Reports NAK status. All isochronous OUT packets aredropped."]
pub type GoutnakstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Others: Reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tstctl {
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
    Testfe = 5,
}
impl From<Tstctl> for u8 {
    #[inline(always)]
    fn from(variant: Tstctl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Tstctl {
    type Ux = u8;
}
#[doc = "Field `tstctl` reader - Others: Reserved."]
pub type TstctlR = crate::FieldReader<Tstctl>;
impl TstctlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Tstctl> {
        match self.bits {
            0 => Some(Tstctl::Disabled),
            1 => Some(Tstctl::Testj),
            2 => Some(Tstctl::Testk),
            3 => Some(Tstctl::Testsn),
            4 => Some(Tstctl::Testpm),
            5 => Some(Tstctl::Testfe),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tstctl::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_testj(&self) -> bool {
        *self == Tstctl::Testj
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_testk(&self) -> bool {
        *self == Tstctl::Testk
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_testsn(&self) -> bool {
        *self == Tstctl::Testsn
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_testpm(&self) -> bool {
        *self == Tstctl::Testpm
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_testfe(&self) -> bool {
        *self == Tstctl::Testfe
    }
}
#[doc = "Field `tstctl` writer - Others: Reserved."]
pub type TstctlW<'a, REG> = crate::FieldWriter<'a, REG, 3, Tstctl>;
impl<'a, REG> TstctlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tstctl::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn testj(self) -> &'a mut crate::W<REG> {
        self.variant(Tstctl::Testj)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn testk(self) -> &'a mut crate::W<REG> {
        self.variant(Tstctl::Testk)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn testsn(self) -> &'a mut crate::W<REG> {
        self.variant(Tstctl::Testsn)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn testpm(self) -> &'a mut crate::W<REG> {
        self.variant(Tstctl::Testpm)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn testfe(self) -> &'a mut crate::W<REG> {
        self.variant(Tstctl::Testfe)
    }
}
#[doc = "Field `sgnpinnak` reader - A write to this field sets the Global Non-periodic IN NAK. The application uses this bit to send a NAK handshake on all nonperiodic IN endpoints. The core can also Set this bit when a timeout condition is detected on a non-periodic endpoint in shared FIFO operation. The application must Set this bit only after making sure that the Global IN NAK Effective bit in the Core Interrupt Register (GINTSTS.GINNakEff) is cleared"]
pub type SgnpinnakR = crate::BitReader;
#[doc = "A write to this field sets the Global Non-periodic IN NAK. The application uses this bit to send a NAK handshake on all nonperiodic IN endpoints. The core can also Set this bit when a timeout condition is detected on a non-periodic endpoint in shared FIFO operation. The application must Set this bit only after making sure that the Global IN NAK Effective bit in the Core Interrupt Register (GINTSTS.GINNakEff) is cleared\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sgnpinnak {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sgnpinnak> for bool {
    #[inline(always)]
    fn from(variant: Sgnpinnak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sgnpinnak` writer - A write to this field sets the Global Non-periodic IN NAK. The application uses this bit to send a NAK handshake on all nonperiodic IN endpoints. The core can also Set this bit when a timeout condition is detected on a non-periodic endpoint in shared FIFO operation. The application must Set this bit only after making sure that the Global IN NAK Effective bit in the Core Interrupt Register (GINTSTS.GINNakEff) is cleared"]
pub type SgnpinnakW<'a, REG> = crate::BitWriter<'a, REG, Sgnpinnak>;
impl<'a, REG> SgnpinnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sgnpinnak::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sgnpinnak::Enabled)
    }
}
#[doc = "Field `CGNPInNak` reader - A write to this field clears the Global Non-periodic IN NAK."]
pub type CgnpinNakR = crate::BitReader;
#[doc = "A write to this field clears the Global Non-periodic IN NAK.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgnpinNak {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<CgnpinNak> for bool {
    #[inline(always)]
    fn from(variant: CgnpinNak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `CGNPInNak` writer - A write to this field clears the Global Non-periodic IN NAK."]
pub type CgnpinNakW<'a, REG> = crate::BitWriter<'a, REG, CgnpinNak>;
impl<'a, REG> CgnpinNakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(CgnpinNak::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(CgnpinNak::Enable)
    }
}
#[doc = "Field `sgoutnak` reader - A write to this field sets the Global OUT NAK.The application uses this bit to send a NAK handshake on all OUT endpoints. The application must Set the this bit only after making sure that the Global OUT NAK Effective bit in the Core Interrupt Register GINTSTS.GOUTNakEff) is cleared."]
pub type SgoutnakR = crate::BitReader;
#[doc = "A write to this field sets the Global OUT NAK.The application uses this bit to send a NAK handshake on all OUT endpoints. The application must Set the this bit only after making sure that the Global OUT NAK Effective bit in the Core Interrupt Register GINTSTS.GOUTNakEff) is cleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sgoutnak {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sgoutnak> for bool {
    #[inline(always)]
    fn from(variant: Sgoutnak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sgoutnak` writer - A write to this field sets the Global OUT NAK.The application uses this bit to send a NAK handshake on all OUT endpoints. The application must Set the this bit only after making sure that the Global OUT NAK Effective bit in the Core Interrupt Register GINTSTS.GOUTNakEff) is cleared."]
pub type SgoutnakW<'a, REG> = crate::BitWriter<'a, REG, Sgoutnak>;
impl<'a, REG> SgoutnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sgoutnak::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sgoutnak::Enabled)
    }
}
#[doc = "Field `cgoutnak` reader - A write to this field clears the Global OUT NAK."]
pub type CgoutnakR = crate::BitReader;
#[doc = "A write to this field clears the Global OUT NAK.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cgoutnak {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Cgoutnak> for bool {
    #[inline(always)]
    fn from(variant: Cgoutnak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cgoutnak` writer - A write to this field clears the Global OUT NAK."]
pub type CgoutnakW<'a, REG> = crate::BitWriter<'a, REG, Cgoutnak>;
impl<'a, REG> CgoutnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cgoutnak::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cgoutnak::Enabled)
    }
}
#[doc = "The application uses this bit to indicate that registerprogramming is completed after a wake-up from Power Downmode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pwronprgdone {
    #[doc = "0: `0`"]
    Notdone = 0,
    #[doc = "1: `1`"]
    Done = 1,
}
impl From<Pwronprgdone> for bool {
    #[inline(always)]
    fn from(variant: Pwronprgdone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pwronprgdone` reader - The application uses this bit to indicate that registerprogramming is completed after a wake-up from Power Downmode."]
pub type PwronprgdoneR = crate::BitReader<Pwronprgdone>;
impl PwronprgdoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pwronprgdone {
        match self.bits {
            false => Pwronprgdone::Notdone,
            true => Pwronprgdone::Done,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notdone(&self) -> bool {
        *self == Pwronprgdone::Notdone
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_done(&self) -> bool {
        *self == Pwronprgdone::Done
    }
}
#[doc = "Field `pwronprgdone` writer - The application uses this bit to indicate that registerprogramming is completed after a wake-up from Power Downmode."]
pub type PwronprgdoneW<'a, REG> = crate::BitWriter<'a, REG, Pwronprgdone>;
impl<'a, REG> PwronprgdoneW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notdone(self) -> &'a mut crate::W<REG> {
        self.variant(Pwronprgdone::Notdone)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn done(self) -> &'a mut crate::W<REG> {
        self.variant(Pwronprgdone::Done)
    }
}
#[doc = "GMC must be programmed only once after initialization.Applicable only for Scatter/Gather DMA mode. This indicates the number of packets to be serviced for that end point before moving to the next end point. It is only for non-periodic end points. When Scatter/Gather DMA mode is disabled, this field isreserved. and reads 0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Gmc {
    #[doc = "0: `0`"]
    Notvalid = 0,
    #[doc = "1: `1`"]
    Onepacket = 1,
    #[doc = "2: `10`"]
    Twopacket = 2,
    #[doc = "3: `11`"]
    Threepacket = 3,
}
impl From<Gmc> for u8 {
    #[inline(always)]
    fn from(variant: Gmc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Gmc {
    type Ux = u8;
}
#[doc = "Field `gmc` reader - GMC must be programmed only once after initialization.Applicable only for Scatter/Gather DMA mode. This indicates the number of packets to be serviced for that end point before moving to the next end point. It is only for non-periodic end points. When Scatter/Gather DMA mode is disabled, this field isreserved. and reads 0."]
pub type GmcR = crate::FieldReader<Gmc>;
impl GmcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gmc {
        match self.bits {
            0 => Gmc::Notvalid,
            1 => Gmc::Onepacket,
            2 => Gmc::Twopacket,
            3 => Gmc::Threepacket,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notvalid(&self) -> bool {
        *self == Gmc::Notvalid
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_onepacket(&self) -> bool {
        *self == Gmc::Onepacket
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_twopacket(&self) -> bool {
        *self == Gmc::Twopacket
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_threepacket(&self) -> bool {
        *self == Gmc::Threepacket
    }
}
#[doc = "Field `gmc` writer - GMC must be programmed only once after initialization.Applicable only for Scatter/Gather DMA mode. This indicates the number of packets to be serviced for that end point before moving to the next end point. It is only for non-periodic end points. When Scatter/Gather DMA mode is disabled, this field isreserved. and reads 0."]
pub type GmcW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Gmc>;
impl<'a, REG> GmcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notvalid(self) -> &'a mut crate::W<REG> {
        self.variant(Gmc::Notvalid)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn onepacket(self) -> &'a mut crate::W<REG> {
        self.variant(Gmc::Onepacket)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn twopacket(self) -> &'a mut crate::W<REG> {
        self.variant(Gmc::Twopacket)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn threepacket(self) -> &'a mut crate::W<REG> {
        self.variant(Gmc::Threepacket)
    }
}
#[doc = "Do NOT program IgnrFrmNum bit to 1'b1 when the core is operating in threshold mode. When Scatter/Gather DMA mode is enabled this feature is not applicable to High Speed, High bandwidth transfers. When this bit is enabled, there must be only one packet per descriptor. In Scatter/Gather DMA mode, if this bit is enabled, the packets are not flushed when a ISOC IN token is received for an elapsed frame. When Scatter/Gather DMA mode is disabled, this field is used by the application to enable periodic transfer interrupt. The application can program periodic endpoint transfers for multiple (micro)frames. 0: periodic transfer interrupt feature is disabled, application needs to program transfers for periodic endpoints every (micro)frame 1: periodic transfer interrupt feature is enabled, application can program transfers for multiple (micro)frames for periodic endpoints. In non Scatter/Gather DMA mode the application will receive transfer complete interrupt after transfers for multiple (micro)frames are completed.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignrfrmnum {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ignrfrmnum> for bool {
    #[inline(always)]
    fn from(variant: Ignrfrmnum) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ignrfrmnum` reader - Do NOT program IgnrFrmNum bit to 1'b1 when the core is operating in threshold mode. When Scatter/Gather DMA mode is enabled this feature is not applicable to High Speed, High bandwidth transfers. When this bit is enabled, there must be only one packet per descriptor. In Scatter/Gather DMA mode, if this bit is enabled, the packets are not flushed when a ISOC IN token is received for an elapsed frame. When Scatter/Gather DMA mode is disabled, this field is used by the application to enable periodic transfer interrupt. The application can program periodic endpoint transfers for multiple (micro)frames. 0: periodic transfer interrupt feature is disabled, application needs to program transfers for periodic endpoints every (micro)frame 1: periodic transfer interrupt feature is enabled, application can program transfers for multiple (micro)frames for periodic endpoints. In non Scatter/Gather DMA mode the application will receive transfer complete interrupt after transfers for multiple (micro)frames are completed."]
pub type IgnrfrmnumR = crate::BitReader<Ignrfrmnum>;
impl IgnrfrmnumR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ignrfrmnum {
        match self.bits {
            false => Ignrfrmnum::Disabled,
            true => Ignrfrmnum::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ignrfrmnum::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ignrfrmnum::Enabled
    }
}
#[doc = "Field `ignrfrmnum` writer - Do NOT program IgnrFrmNum bit to 1'b1 when the core is operating in threshold mode. When Scatter/Gather DMA mode is enabled this feature is not applicable to High Speed, High bandwidth transfers. When this bit is enabled, there must be only one packet per descriptor. In Scatter/Gather DMA mode, if this bit is enabled, the packets are not flushed when a ISOC IN token is received for an elapsed frame. When Scatter/Gather DMA mode is disabled, this field is used by the application to enable periodic transfer interrupt. The application can program periodic endpoint transfers for multiple (micro)frames. 0: periodic transfer interrupt feature is disabled, application needs to program transfers for periodic endpoints every (micro)frame 1: periodic transfer interrupt feature is enabled, application can program transfers for multiple (micro)frames for periodic endpoints. In non Scatter/Gather DMA mode the application will receive transfer complete interrupt after transfers for multiple (micro)frames are completed."]
pub type IgnrfrmnumW<'a, REG> = crate::BitWriter<'a, REG, Ignrfrmnum>;
impl<'a, REG> IgnrfrmnumW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ignrfrmnum::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ignrfrmnum::Enabled)
    }
}
#[doc = "Set NAK automatically on babble (NakOnBble). The core sets NAK automatically for the endpoint on which babble is received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nakonbble {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Nakonbble> for bool {
    #[inline(always)]
    fn from(variant: Nakonbble) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nakonbble` reader - Set NAK automatically on babble (NakOnBble). The core sets NAK automatically for the endpoint on which babble is received."]
pub type NakonbbleR = crate::BitReader<Nakonbble>;
impl NakonbbleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nakonbble {
        match self.bits {
            false => Nakonbble::Disabled,
            true => Nakonbble::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Nakonbble::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Nakonbble::Enabled
    }
}
#[doc = "Field `nakonbble` writer - Set NAK automatically on babble (NakOnBble). The core sets NAK automatically for the endpoint on which babble is received."]
pub type NakonbbleW<'a, REG> = crate::BitWriter<'a, REG, Nakonbble>;
impl<'a, REG> NakonbbleW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nakonbble::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nakonbble::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When the application sets this bit, the core initiates remote signaling to wake up the USB host. The application must Set this bit to instruct the core to exit the Suspend state. As specified in the USB 2.0 specification, the application must clear this bit 115 ms after setting it. Remote Wakeup Signaling (RmtWkUpSig) When LPM is enabled, In L1 state the behavior of this bit is as follows: When the application sets this bit, the core initiates L1 remote signaling to wake up the USB host. The application must set this bit to instruct the core to exit the Sleep state. As specified in the LPM specification, the hardware will automatically clear this bit after a time of 50us (TL1DevDrvResume) after set by application. Application should not set this bit when GLPMCFG bRemoteWake from the previous LPM transaction was zero."]
    #[inline(always)]
    pub fn rmtwkupsig(&self) -> RmtwkupsigR {
        RmtwkupsigR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - The application uses this bit to signal the otg core to do a soft disconnect. As long as this bit is Set, the host does not see that the device is connected, and the device does not receive signals on the USB. The core stays in the disconnected state until the application clears this bit. There is a minimum duration for which the core must keep this bit set. When this bit is cleared after a soft disconnect, the core drives the phy_opmode_o signal on the ULPI, which generates a device connect event to the USB host. When the device is reconnected, the USB host restarts device enumeration.;"]
    #[inline(always)]
    pub fn sftdiscon(&self) -> SftdisconR {
        SftdisconR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Defines IN NAK conditions."]
    #[inline(always)]
    pub fn gnpinnaksts(&self) -> GnpinnakstsR {
        GnpinnakstsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Reports NAK status. All isochronous OUT packets aredropped."]
    #[inline(always)]
    pub fn goutnaksts(&self) -> GoutnakstsR {
        GoutnakstsR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:6 - Others: Reserved."]
    #[inline(always)]
    pub fn tstctl(&self) -> TstctlR {
        TstctlR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bit 7 - A write to this field sets the Global Non-periodic IN NAK. The application uses this bit to send a NAK handshake on all nonperiodic IN endpoints. The core can also Set this bit when a timeout condition is detected on a non-periodic endpoint in shared FIFO operation. The application must Set this bit only after making sure that the Global IN NAK Effective bit in the Core Interrupt Register (GINTSTS.GINNakEff) is cleared"]
    #[inline(always)]
    pub fn sgnpinnak(&self) -> SgnpinnakR {
        SgnpinnakR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - A write to this field clears the Global Non-periodic IN NAK."]
    #[inline(always)]
    pub fn cgnpin_nak(&self) -> CgnpinNakR {
        CgnpinNakR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - A write to this field sets the Global OUT NAK.The application uses this bit to send a NAK handshake on all OUT endpoints. The application must Set the this bit only after making sure that the Global OUT NAK Effective bit in the Core Interrupt Register GINTSTS.GOUTNakEff) is cleared."]
    #[inline(always)]
    pub fn sgoutnak(&self) -> SgoutnakR {
        SgoutnakR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - A write to this field clears the Global OUT NAK."]
    #[inline(always)]
    pub fn cgoutnak(&self) -> CgoutnakR {
        CgoutnakR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - The application uses this bit to indicate that registerprogramming is completed after a wake-up from Power Downmode."]
    #[inline(always)]
    pub fn pwronprgdone(&self) -> PwronprgdoneR {
        PwronprgdoneR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bits 13:14 - GMC must be programmed only once after initialization.Applicable only for Scatter/Gather DMA mode. This indicates the number of packets to be serviced for that end point before moving to the next end point. It is only for non-periodic end points. When Scatter/Gather DMA mode is disabled, this field isreserved. and reads 0."]
    #[inline(always)]
    pub fn gmc(&self) -> GmcR {
        GmcR::new(((self.bits >> 13) & 3) as u8)
    }
    #[doc = "Bit 15 - Do NOT program IgnrFrmNum bit to 1'b1 when the core is operating in threshold mode. When Scatter/Gather DMA mode is enabled this feature is not applicable to High Speed, High bandwidth transfers. When this bit is enabled, there must be only one packet per descriptor. In Scatter/Gather DMA mode, if this bit is enabled, the packets are not flushed when a ISOC IN token is received for an elapsed frame. When Scatter/Gather DMA mode is disabled, this field is used by the application to enable periodic transfer interrupt. The application can program periodic endpoint transfers for multiple (micro)frames. 0: periodic transfer interrupt feature is disabled, application needs to program transfers for periodic endpoints every (micro)frame 1: periodic transfer interrupt feature is enabled, application can program transfers for multiple (micro)frames for periodic endpoints. In non Scatter/Gather DMA mode the application will receive transfer complete interrupt after transfers for multiple (micro)frames are completed."]
    #[inline(always)]
    pub fn ignrfrmnum(&self) -> IgnrfrmnumR {
        IgnrfrmnumR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Set NAK automatically on babble (NakOnBble). The core sets NAK automatically for the endpoint on which babble is received."]
    #[inline(always)]
    pub fn nakonbble(&self) -> NakonbbleR {
        NakonbbleR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When the application sets this bit, the core initiates remote signaling to wake up the USB host. The application must Set this bit to instruct the core to exit the Suspend state. As specified in the USB 2.0 specification, the application must clear this bit 115 ms after setting it. Remote Wakeup Signaling (RmtWkUpSig) When LPM is enabled, In L1 state the behavior of this bit is as follows: When the application sets this bit, the core initiates L1 remote signaling to wake up the USB host. The application must set this bit to instruct the core to exit the Sleep state. As specified in the LPM specification, the hardware will automatically clear this bit after a time of 50us (TL1DevDrvResume) after set by application. Application should not set this bit when GLPMCFG bRemoteWake from the previous LPM transaction was zero."]
    #[inline(always)]
    #[must_use]
    pub fn rmtwkupsig(&mut self) -> RmtwkupsigW<DevgrpDctlSpec> {
        RmtwkupsigW::new(self, 0)
    }
    #[doc = "Bit 1 - The application uses this bit to signal the otg core to do a soft disconnect. As long as this bit is Set, the host does not see that the device is connected, and the device does not receive signals on the USB. The core stays in the disconnected state until the application clears this bit. There is a minimum duration for which the core must keep this bit set. When this bit is cleared after a soft disconnect, the core drives the phy_opmode_o signal on the ULPI, which generates a device connect event to the USB host. When the device is reconnected, the USB host restarts device enumeration.;"]
    #[inline(always)]
    #[must_use]
    pub fn sftdiscon(&mut self) -> SftdisconW<DevgrpDctlSpec> {
        SftdisconW::new(self, 1)
    }
    #[doc = "Bit 2 - Defines IN NAK conditions."]
    #[inline(always)]
    #[must_use]
    pub fn gnpinnaksts(&mut self) -> GnpinnakstsW<DevgrpDctlSpec> {
        GnpinnakstsW::new(self, 2)
    }
    #[doc = "Bit 3 - Reports NAK status. All isochronous OUT packets aredropped."]
    #[inline(always)]
    #[must_use]
    pub fn goutnaksts(&mut self) -> GoutnakstsW<DevgrpDctlSpec> {
        GoutnakstsW::new(self, 3)
    }
    #[doc = "Bits 4:6 - Others: Reserved."]
    #[inline(always)]
    #[must_use]
    pub fn tstctl(&mut self) -> TstctlW<DevgrpDctlSpec> {
        TstctlW::new(self, 4)
    }
    #[doc = "Bit 7 - A write to this field sets the Global Non-periodic IN NAK. The application uses this bit to send a NAK handshake on all nonperiodic IN endpoints. The core can also Set this bit when a timeout condition is detected on a non-periodic endpoint in shared FIFO operation. The application must Set this bit only after making sure that the Global IN NAK Effective bit in the Core Interrupt Register (GINTSTS.GINNakEff) is cleared"]
    #[inline(always)]
    #[must_use]
    pub fn sgnpinnak(&mut self) -> SgnpinnakW<DevgrpDctlSpec> {
        SgnpinnakW::new(self, 7)
    }
    #[doc = "Bit 8 - A write to this field clears the Global Non-periodic IN NAK."]
    #[inline(always)]
    #[must_use]
    pub fn cgnpin_nak(&mut self) -> CgnpinNakW<DevgrpDctlSpec> {
        CgnpinNakW::new(self, 8)
    }
    #[doc = "Bit 9 - A write to this field sets the Global OUT NAK.The application uses this bit to send a NAK handshake on all OUT endpoints. The application must Set the this bit only after making sure that the Global OUT NAK Effective bit in the Core Interrupt Register GINTSTS.GOUTNakEff) is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn sgoutnak(&mut self) -> SgoutnakW<DevgrpDctlSpec> {
        SgoutnakW::new(self, 9)
    }
    #[doc = "Bit 10 - A write to this field clears the Global OUT NAK."]
    #[inline(always)]
    #[must_use]
    pub fn cgoutnak(&mut self) -> CgoutnakW<DevgrpDctlSpec> {
        CgoutnakW::new(self, 10)
    }
    #[doc = "Bit 11 - The application uses this bit to indicate that registerprogramming is completed after a wake-up from Power Downmode."]
    #[inline(always)]
    #[must_use]
    pub fn pwronprgdone(&mut self) -> PwronprgdoneW<DevgrpDctlSpec> {
        PwronprgdoneW::new(self, 11)
    }
    #[doc = "Bits 13:14 - GMC must be programmed only once after initialization.Applicable only for Scatter/Gather DMA mode. This indicates the number of packets to be serviced for that end point before moving to the next end point. It is only for non-periodic end points. When Scatter/Gather DMA mode is disabled, this field isreserved. and reads 0."]
    #[inline(always)]
    #[must_use]
    pub fn gmc(&mut self) -> GmcW<DevgrpDctlSpec> {
        GmcW::new(self, 13)
    }
    #[doc = "Bit 15 - Do NOT program IgnrFrmNum bit to 1'b1 when the core is operating in threshold mode. When Scatter/Gather DMA mode is enabled this feature is not applicable to High Speed, High bandwidth transfers. When this bit is enabled, there must be only one packet per descriptor. In Scatter/Gather DMA mode, if this bit is enabled, the packets are not flushed when a ISOC IN token is received for an elapsed frame. When Scatter/Gather DMA mode is disabled, this field is used by the application to enable periodic transfer interrupt. The application can program periodic endpoint transfers for multiple (micro)frames. 0: periodic transfer interrupt feature is disabled, application needs to program transfers for periodic endpoints every (micro)frame 1: periodic transfer interrupt feature is enabled, application can program transfers for multiple (micro)frames for periodic endpoints. In non Scatter/Gather DMA mode the application will receive transfer complete interrupt after transfers for multiple (micro)frames are completed."]
    #[inline(always)]
    #[must_use]
    pub fn ignrfrmnum(&mut self) -> IgnrfrmnumW<DevgrpDctlSpec> {
        IgnrfrmnumW::new(self, 15)
    }
    #[doc = "Bit 16 - Set NAK automatically on babble (NakOnBble). The core sets NAK automatically for the endpoint on which babble is received."]
    #[inline(always)]
    #[must_use]
    pub fn nakonbble(&mut self) -> NakonbbleW<DevgrpDctlSpec> {
        NakonbbleW::new(self, 16)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDctlSpec;
impl crate::RegisterSpec for DevgrpDctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 2052u64;
}
#[doc = "`read()` method returns [`devgrp_dctl::R`](R) reader structure"]
impl crate::Readable for DevgrpDctlSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dctl::W`](W) writer structure"]
impl crate::Writable for DevgrpDctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dctl to value 0"]
impl crate::Resettable for DevgrpDctlSpec {
    const RESET_VALUE: u32 = 0;
}
