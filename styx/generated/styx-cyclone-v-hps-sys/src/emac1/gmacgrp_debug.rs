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
#[doc = "Register `gmacgrp_Debug` reader"]
pub type R = crate::R<GmacgrpDebugSpec>;
#[doc = "Register `gmacgrp_Debug` writer"]
pub type W = crate::W<GmacgrpDebugSpec>;
#[doc = "When high, this bit indicates that the MAC GMII or MII receive protocol engine is actively receiving data and not in IDLE state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rpests {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rpests> for bool {
    #[inline(always)]
    fn from(variant: Rpests) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rpests` reader - When high, this bit indicates that the MAC GMII or MII receive protocol engine is actively receiving data and not in IDLE state."]
pub type RpestsR = crate::BitReader<Rpests>;
impl RpestsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rpests {
        match self.bits {
            false => Rpests::Inactive,
            true => Rpests::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rpests::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rpests::Active
    }
}
#[doc = "Field `rpests` writer - When high, this bit indicates that the MAC GMII or MII receive protocol engine is actively receiving data and not in IDLE state."]
pub type RpestsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When high, this field indicates the active state of the small FIFO Read and Write controllers of the MAC Receive Frame Controller Module.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rfcfcsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rfcfcsts> for u8 {
    #[inline(always)]
    fn from(variant: Rfcfcsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rfcfcsts {
    type Ux = u8;
}
#[doc = "Field `rfcfcsts` reader - When high, this field indicates the active state of the small FIFO Read and Write controllers of the MAC Receive Frame Controller Module."]
pub type RfcfcstsR = crate::FieldReader<Rfcfcsts>;
impl RfcfcstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rfcfcsts> {
        match self.bits {
            0 => Some(Rfcfcsts::Inactive),
            1 => Some(Rfcfcsts::Active),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rfcfcsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rfcfcsts::Active
    }
}
#[doc = "Field `rfcfcsts` writer - When high, this field indicates the active state of the small FIFO Read and Write controllers of the MAC Receive Frame Controller Module."]
pub type RfcfcstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "When high, this bit indicates that the MTL Rx FIFO Write Controller is active and is transferring a received frame to the FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rwcsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rwcsts> for bool {
    #[inline(always)]
    fn from(variant: Rwcsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rwcsts` reader - When high, this bit indicates that the MTL Rx FIFO Write Controller is active and is transferring a received frame to the FIFO."]
pub type RwcstsR = crate::BitReader<Rwcsts>;
impl RwcstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rwcsts {
        match self.bits {
            false => Rwcsts::Inactive,
            true => Rwcsts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rwcsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rwcsts::Active
    }
}
#[doc = "Field `rwcsts` writer - When high, this bit indicates that the MTL Rx FIFO Write Controller is active and is transferring a received frame to the FIFO."]
pub type RwcstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This field gives the state of the Rx FIFO read Controller\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rrcsts {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    Rdframedata = 1,
    #[doc = "2: `10`"]
    Rdframestat = 2,
    #[doc = "3: `11`"]
    Flushfrds = 3,
}
impl From<Rrcsts> for u8 {
    #[inline(always)]
    fn from(variant: Rrcsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rrcsts {
    type Ux = u8;
}
#[doc = "Field `rrcsts` reader - This field gives the state of the Rx FIFO read Controller"]
pub type RrcstsR = crate::FieldReader<Rrcsts>;
impl RrcstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rrcsts {
        match self.bits {
            0 => Rrcsts::Idle,
            1 => Rrcsts::Rdframedata,
            2 => Rrcsts::Rdframestat,
            3 => Rrcsts::Flushfrds,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == Rrcsts::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rdframedata(&self) -> bool {
        *self == Rrcsts::Rdframedata
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rdframestat(&self) -> bool {
        *self == Rrcsts::Rdframestat
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_flushfrds(&self) -> bool {
        *self == Rrcsts::Flushfrds
    }
}
#[doc = "Field `rrcsts` writer - This field gives the state of the Rx FIFO read Controller"]
pub type RrcstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "This field gives the status of the fill-level of the Rx FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rxfsts {
    #[doc = "0: `0`"]
    Rxfifoempty = 0,
    #[doc = "1: `1`"]
    Rxfifobellvl = 1,
    #[doc = "2: `10`"]
    Rxfifoablvl = 2,
    #[doc = "3: `11`"]
    Rxfifofull = 3,
}
impl From<Rxfsts> for u8 {
    #[inline(always)]
    fn from(variant: Rxfsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rxfsts {
    type Ux = u8;
}
#[doc = "Field `rxfsts` reader - This field gives the status of the fill-level of the Rx FIFO."]
pub type RxfstsR = crate::FieldReader<Rxfsts>;
impl RxfstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfsts {
        match self.bits {
            0 => Rxfsts::Rxfifoempty,
            1 => Rxfsts::Rxfifobellvl,
            2 => Rxfsts::Rxfifoablvl,
            3 => Rxfsts::Rxfifofull,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rxfifoempty(&self) -> bool {
        *self == Rxfsts::Rxfifoempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rxfifobellvl(&self) -> bool {
        *self == Rxfsts::Rxfifobellvl
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rxfifoablvl(&self) -> bool {
        *self == Rxfsts::Rxfifoablvl
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_rxfifofull(&self) -> bool {
        *self == Rxfsts::Rxfifofull
    }
}
#[doc = "Field `rxfsts` writer - This field gives the status of the fill-level of the Rx FIFO."]
pub type RxfstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "When high, this bit indicates that the MAC GMII or MII transmit protocol engine is actively transmitting data and is not in the IDLE state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tpests {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tpests> for bool {
    #[inline(always)]
    fn from(variant: Tpests) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tpests` reader - When high, this bit indicates that the MAC GMII or MII transmit protocol engine is actively transmitting data and is not in the IDLE state."]
pub type TpestsR = crate::BitReader<Tpests>;
impl TpestsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tpests {
        match self.bits {
            false => Tpests::Disabled,
            true => Tpests::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tpests::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tpests::Enabled
    }
}
#[doc = "Field `tpests` writer - When high, this bit indicates that the MAC GMII or MII transmit protocol engine is actively transmitting data and is not in the IDLE state."]
pub type TpestsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This field indicates the state of the MAC Transmit Frame Controller block\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tfcsts {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    Waitifg = 1,
    #[doc = "2: `10`"]
    Xtpause = 2,
    #[doc = "3: `11`"]
    Xtinfrm = 3,
}
impl From<Tfcsts> for u8 {
    #[inline(always)]
    fn from(variant: Tfcsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Tfcsts {
    type Ux = u8;
}
#[doc = "Field `tfcsts` reader - This field indicates the state of the MAC Transmit Frame Controller block"]
pub type TfcstsR = crate::FieldReader<Tfcsts>;
impl TfcstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tfcsts {
        match self.bits {
            0 => Tfcsts::Idle,
            1 => Tfcsts::Waitifg,
            2 => Tfcsts::Xtpause,
            3 => Tfcsts::Xtinfrm,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == Tfcsts::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_waitifg(&self) -> bool {
        *self == Tfcsts::Waitifg
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_xtpause(&self) -> bool {
        *self == Tfcsts::Xtpause
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_xtinfrm(&self) -> bool {
        *self == Tfcsts::Xtinfrm
    }
}
#[doc = "Field `tfcsts` writer - This field indicates the state of the MAC Transmit Frame Controller block"]
pub type TfcstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "When high, this bit indicates that the MAC transmitter is in the PAUSE condition (in the full-duplex only mode) and hence does not schedule any frame for transmission.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txpaused {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txpaused> for bool {
    #[inline(always)]
    fn from(variant: Txpaused) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txpaused` reader - When high, this bit indicates that the MAC transmitter is in the PAUSE condition (in the full-duplex only mode) and hence does not schedule any frame for transmission."]
pub type TxpausedR = crate::BitReader<Txpaused>;
impl TxpausedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txpaused {
        match self.bits {
            false => Txpaused::Disable,
            true => Txpaused::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Txpaused::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txpaused::Enabled
    }
}
#[doc = "Field `txpaused` writer - When high, this bit indicates that the MAC transmitter is in the PAUSE condition (in the full-duplex only mode) and hence does not schedule any frame for transmission."]
pub type TxpausedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This field indicates the state of the Tx FIFO Read Controller\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Trcsts {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    Readstate = 1,
    #[doc = "2: `10`"]
    Waittxstat = 2,
    #[doc = "3: `11`"]
    Wrtxstat = 3,
}
impl From<Trcsts> for u8 {
    #[inline(always)]
    fn from(variant: Trcsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Trcsts {
    type Ux = u8;
}
#[doc = "Field `trcsts` reader - This field indicates the state of the Tx FIFO Read Controller"]
pub type TrcstsR = crate::FieldReader<Trcsts>;
impl TrcstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Trcsts {
        match self.bits {
            0 => Trcsts::Idle,
            1 => Trcsts::Readstate,
            2 => Trcsts::Waittxstat,
            3 => Trcsts::Wrtxstat,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == Trcsts::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_readstate(&self) -> bool {
        *self == Trcsts::Readstate
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_waittxstat(&self) -> bool {
        *self == Trcsts::Waittxstat
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_wrtxstat(&self) -> bool {
        *self == Trcsts::Wrtxstat
    }
}
#[doc = "Field `trcsts` writer - This field indicates the state of the Tx FIFO Read Controller"]
pub type TrcstsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "When high, this bit indicates that the MTL Tx FIFO Write Controller is active and transferring data to the Tx FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Twcsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Twcsts> for bool {
    #[inline(always)]
    fn from(variant: Twcsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `twcsts` reader - When high, this bit indicates that the MTL Tx FIFO Write Controller is active and transferring data to the Tx FIFO."]
pub type TwcstsR = crate::BitReader<Twcsts>;
impl TwcstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Twcsts {
        match self.bits {
            false => Twcsts::Inactive,
            true => Twcsts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Twcsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Twcsts::Active
    }
}
#[doc = "Field `twcsts` writer - When high, this bit indicates that the MTL Tx FIFO Write Controller is active and transferring data to the Tx FIFO."]
pub type TwcstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When high, this bit indicates that the MTL Tx FIFO is not empty and some data is left for transmission.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txfsts> for bool {
    #[inline(always)]
    fn from(variant: Txfsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfsts` reader - When high, this bit indicates that the MTL Tx FIFO is not empty and some data is left for transmission."]
pub type TxfstsR = crate::BitReader<Txfsts>;
impl TxfstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfsts {
        match self.bits {
            false => Txfsts::Inactive,
            true => Txfsts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txfsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txfsts::Active
    }
}
#[doc = "Field `txfsts` writer - When high, this bit indicates that the MTL Tx FIFO is not empty and some data is left for transmission."]
pub type TxfstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When high, this bit indicates that the MTL TxStatus FIFO is full. Therefore, the MTL cannot accept any more frames for transmission.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txstsfsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txstsfsts> for bool {
    #[inline(always)]
    fn from(variant: Txstsfsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txstsfsts` reader - When high, this bit indicates that the MTL TxStatus FIFO is full. Therefore, the MTL cannot accept any more frames for transmission."]
pub type TxstsfstsR = crate::BitReader<Txstsfsts>;
impl TxstsfstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txstsfsts {
        match self.bits {
            false => Txstsfsts::Inactive,
            true => Txstsfsts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txstsfsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txstsfsts::Active
    }
}
#[doc = "Field `txstsfsts` writer - When high, this bit indicates that the MTL TxStatus FIFO is full. Therefore, the MTL cannot accept any more frames for transmission."]
pub type TxstsfstsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When high, this bit indicates that the MAC GMII or MII receive protocol engine is actively receiving data and not in IDLE state."]
    #[inline(always)]
    pub fn rpests(&self) -> RpestsR {
        RpestsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - When high, this field indicates the active state of the small FIFO Read and Write controllers of the MAC Receive Frame Controller Module."]
    #[inline(always)]
    pub fn rfcfcsts(&self) -> RfcfcstsR {
        RfcfcstsR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 4 - When high, this bit indicates that the MTL Rx FIFO Write Controller is active and is transferring a received frame to the FIFO."]
    #[inline(always)]
    pub fn rwcsts(&self) -> RwcstsR {
        RwcstsR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:6 - This field gives the state of the Rx FIFO read Controller"]
    #[inline(always)]
    pub fn rrcsts(&self) -> RrcstsR {
        RrcstsR::new(((self.bits >> 5) & 3) as u8)
    }
    #[doc = "Bits 8:9 - This field gives the status of the fill-level of the Rx FIFO."]
    #[inline(always)]
    pub fn rxfsts(&self) -> RxfstsR {
        RxfstsR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bit 16 - When high, this bit indicates that the MAC GMII or MII transmit protocol engine is actively transmitting data and is not in the IDLE state."]
    #[inline(always)]
    pub fn tpests(&self) -> TpestsR {
        TpestsR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:18 - This field indicates the state of the MAC Transmit Frame Controller block"]
    #[inline(always)]
    pub fn tfcsts(&self) -> TfcstsR {
        TfcstsR::new(((self.bits >> 17) & 3) as u8)
    }
    #[doc = "Bit 19 - When high, this bit indicates that the MAC transmitter is in the PAUSE condition (in the full-duplex only mode) and hence does not schedule any frame for transmission."]
    #[inline(always)]
    pub fn txpaused(&self) -> TxpausedR {
        TxpausedR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bits 20:21 - This field indicates the state of the Tx FIFO Read Controller"]
    #[inline(always)]
    pub fn trcsts(&self) -> TrcstsR {
        TrcstsR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bit 22 - When high, this bit indicates that the MTL Tx FIFO Write Controller is active and transferring data to the Tx FIFO."]
    #[inline(always)]
    pub fn twcsts(&self) -> TwcstsR {
        TwcstsR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 24 - When high, this bit indicates that the MTL Tx FIFO is not empty and some data is left for transmission."]
    #[inline(always)]
    pub fn txfsts(&self) -> TxfstsR {
        TxfstsR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - When high, this bit indicates that the MTL TxStatus FIFO is full. Therefore, the MTL cannot accept any more frames for transmission."]
    #[inline(always)]
    pub fn txstsfsts(&self) -> TxstsfstsR {
        TxstsfstsR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When high, this bit indicates that the MAC GMII or MII receive protocol engine is actively receiving data and not in IDLE state."]
    #[inline(always)]
    #[must_use]
    pub fn rpests(&mut self) -> RpestsW<GmacgrpDebugSpec> {
        RpestsW::new(self, 0)
    }
    #[doc = "Bits 1:2 - When high, this field indicates the active state of the small FIFO Read and Write controllers of the MAC Receive Frame Controller Module."]
    #[inline(always)]
    #[must_use]
    pub fn rfcfcsts(&mut self) -> RfcfcstsW<GmacgrpDebugSpec> {
        RfcfcstsW::new(self, 1)
    }
    #[doc = "Bit 4 - When high, this bit indicates that the MTL Rx FIFO Write Controller is active and is transferring a received frame to the FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rwcsts(&mut self) -> RwcstsW<GmacgrpDebugSpec> {
        RwcstsW::new(self, 4)
    }
    #[doc = "Bits 5:6 - This field gives the state of the Rx FIFO read Controller"]
    #[inline(always)]
    #[must_use]
    pub fn rrcsts(&mut self) -> RrcstsW<GmacgrpDebugSpec> {
        RrcstsW::new(self, 5)
    }
    #[doc = "Bits 8:9 - This field gives the status of the fill-level of the Rx FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rxfsts(&mut self) -> RxfstsW<GmacgrpDebugSpec> {
        RxfstsW::new(self, 8)
    }
    #[doc = "Bit 16 - When high, this bit indicates that the MAC GMII or MII transmit protocol engine is actively transmitting data and is not in the IDLE state."]
    #[inline(always)]
    #[must_use]
    pub fn tpests(&mut self) -> TpestsW<GmacgrpDebugSpec> {
        TpestsW::new(self, 16)
    }
    #[doc = "Bits 17:18 - This field indicates the state of the MAC Transmit Frame Controller block"]
    #[inline(always)]
    #[must_use]
    pub fn tfcsts(&mut self) -> TfcstsW<GmacgrpDebugSpec> {
        TfcstsW::new(self, 17)
    }
    #[doc = "Bit 19 - When high, this bit indicates that the MAC transmitter is in the PAUSE condition (in the full-duplex only mode) and hence does not schedule any frame for transmission."]
    #[inline(always)]
    #[must_use]
    pub fn txpaused(&mut self) -> TxpausedW<GmacgrpDebugSpec> {
        TxpausedW::new(self, 19)
    }
    #[doc = "Bits 20:21 - This field indicates the state of the Tx FIFO Read Controller"]
    #[inline(always)]
    #[must_use]
    pub fn trcsts(&mut self) -> TrcstsW<GmacgrpDebugSpec> {
        TrcstsW::new(self, 20)
    }
    #[doc = "Bit 22 - When high, this bit indicates that the MTL Tx FIFO Write Controller is active and transferring data to the Tx FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn twcsts(&mut self) -> TwcstsW<GmacgrpDebugSpec> {
        TwcstsW::new(self, 22)
    }
    #[doc = "Bit 24 - When high, this bit indicates that the MTL Tx FIFO is not empty and some data is left for transmission."]
    #[inline(always)]
    #[must_use]
    pub fn txfsts(&mut self) -> TxfstsW<GmacgrpDebugSpec> {
        TxfstsW::new(self, 24)
    }
    #[doc = "Bit 25 - When high, this bit indicates that the MTL TxStatus FIFO is full. Therefore, the MTL cannot accept any more frames for transmission."]
    #[inline(always)]
    #[must_use]
    pub fn txstsfsts(&mut self) -> TxstsfstsW<GmacgrpDebugSpec> {
        TxstsfstsW::new(self, 25)
    }
}
#[doc = "The Debug register gives the status of all main blocks of the transmit and receive data-paths and the FIFOs. An all-zero status indicates that the MAC is in idle state (and FIFOs are empty) and no activity is going on in the data-paths.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_debug::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpDebugSpec;
impl crate::RegisterSpec for GmacgrpDebugSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`gmacgrp_debug::R`](R) reader structure"]
impl crate::Readable for GmacgrpDebugSpec {}
#[doc = "`reset()` method sets gmacgrp_Debug to value 0"]
impl crate::Resettable for GmacgrpDebugSpec {
    const RESET_VALUE: u32 = 0;
}
