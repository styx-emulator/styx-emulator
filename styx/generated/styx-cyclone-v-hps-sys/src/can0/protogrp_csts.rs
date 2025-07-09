// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `protogrp_CSTS` reader"]
pub type R = crate::R<ProtogrpCstsSpec>;
#[doc = "Register `protogrp_CSTS` writer"]
pub type W = crate::W<ProtogrpCstsSpec>;
#[doc = "The LEC field holds a code which indicates the type of the last error to occur on the CAN bus. This field will be cleared to 0 when a message has been transferred (reception or transmission) without error.\n\nValue on reset: 7"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Lec {
    #[doc = "0: `0`"]
    NoError = 0,
    #[doc = "1: `1`"]
    StuffError = 1,
    #[doc = "2: `10`"]
    FormError = 2,
    #[doc = "3: `11`"]
    AckError = 3,
    #[doc = "4: `100`"]
    Bit1error = 4,
    #[doc = "5: `101`"]
    Bit0error = 5,
    #[doc = "6: `110`"]
    Crcerror = 6,
    #[doc = "7: `111`"]
    NoChange = 7,
}
impl From<Lec> for u8 {
    #[inline(always)]
    fn from(variant: Lec) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Lec {
    type Ux = u8;
}
#[doc = "Field `LEC` reader - The LEC field holds a code which indicates the type of the last error to occur on the CAN bus. This field will be cleared to 0 when a message has been transferred (reception or transmission) without error."]
pub type LecR = crate::FieldReader<Lec>;
impl LecR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lec {
        match self.bits {
            0 => Lec::NoError,
            1 => Lec::StuffError,
            2 => Lec::FormError,
            3 => Lec::AckError,
            4 => Lec::Bit1error,
            5 => Lec::Bit0error,
            6 => Lec::Crcerror,
            7 => Lec::NoChange,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_error(&self) -> bool {
        *self == Lec::NoError
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_stuff_error(&self) -> bool {
        *self == Lec::StuffError
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_form_error(&self) -> bool {
        *self == Lec::FormError
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_ack_error(&self) -> bool {
        *self == Lec::AckError
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_bit1error(&self) -> bool {
        *self == Lec::Bit1error
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_bit0error(&self) -> bool {
        *self == Lec::Bit0error
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_crcerror(&self) -> bool {
        *self == Lec::Crcerror
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_no_change(&self) -> bool {
        *self == Lec::NoChange
    }
}
#[doc = "Field `LEC` writer - The LEC field holds a code which indicates the type of the last error to occur on the CAN bus. This field will be cleared to 0 when a message has been transferred (reception or transmission) without error."]
pub type LecW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Transmitted a Message Successfully\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxOk {
    #[doc = "0: `0`"]
    NoTxOk = 0,
    #[doc = "1: `1`"]
    TxOk = 1,
}
impl From<TxOk> for bool {
    #[inline(always)]
    fn from(variant: TxOk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxOK` reader - Transmitted a Message Successfully"]
pub type TxOkR = crate::BitReader<TxOk>;
impl TxOkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxOk {
        match self.bits {
            false => TxOk::NoTxOk,
            true => TxOk::TxOk,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_tx_ok(&self) -> bool {
        *self == TxOk::NoTxOk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_tx_ok(&self) -> bool {
        *self == TxOk::TxOk
    }
}
#[doc = "Field `TxOK` writer - Transmitted a Message Successfully"]
pub type TxOkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Received a Message Successfully\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxOk {
    #[doc = "0: `0`"]
    NoRxOk = 0,
    #[doc = "1: `1`"]
    RxOk = 1,
}
impl From<RxOk> for bool {
    #[inline(always)]
    fn from(variant: RxOk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `RxOK` reader - Received a Message Successfully"]
pub type RxOkR = crate::BitReader<RxOk>;
impl RxOkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> RxOk {
        match self.bits {
            false => RxOk::NoRxOk,
            true => RxOk::RxOk,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_rx_ok(&self) -> bool {
        *self == RxOk::NoRxOk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rx_ok(&self) -> bool {
        *self == RxOk::RxOk
    }
}
#[doc = "Field `RxOK` writer - Received a Message Successfully"]
pub type RxOkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Error Passive\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epass {
    #[doc = "0: `0`"]
    Active = 0,
    #[doc = "1: `1`"]
    Passive = 1,
}
impl From<Epass> for bool {
    #[inline(always)]
    fn from(variant: Epass) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `EPASS` reader - Error Passive"]
pub type EpassR = crate::BitReader<Epass>;
impl EpassR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Epass {
        match self.bits {
            false => Epass::Active,
            true => Epass::Passive,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Epass::Active
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_passive(&self) -> bool {
        *self == Epass::Passive
    }
}
#[doc = "Field `EPASS` writer - Error Passive"]
pub type EpassW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Warning Status\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ewarn {
    #[doc = "0: `0`"]
    BelowLimit = 0,
    #[doc = "1: `1`"]
    AboveLimit = 1,
}
impl From<Ewarn> for bool {
    #[inline(always)]
    fn from(variant: Ewarn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `EWarn` reader - Warning Status"]
pub type EwarnR = crate::BitReader<Ewarn>;
impl EwarnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ewarn {
        match self.bits {
            false => Ewarn::BelowLimit,
            true => Ewarn::AboveLimit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_below_limit(&self) -> bool {
        *self == Ewarn::BelowLimit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_above_limit(&self) -> bool {
        *self == Ewarn::AboveLimit
    }
}
#[doc = "Field `EWarn` writer - Warning Status"]
pub type EwarnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Bus_Off Status\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boff {
    #[doc = "0: `0`"]
    NotBusOff = 0,
    #[doc = "1: `1`"]
    BusOff = 1,
}
impl From<Boff> for bool {
    #[inline(always)]
    fn from(variant: Boff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `BOff` reader - Bus_Off Status"]
pub type BoffR = crate::BitReader<Boff>;
impl BoffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Boff {
        match self.bits {
            false => Boff::NotBusOff,
            true => Boff::BusOff,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_bus_off(&self) -> bool {
        *self == Boff::NotBusOff
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_bus_off(&self) -> bool {
        *self == Boff::BusOff
    }
}
#[doc = "Field `BOff` writer - Bus_Off Status"]
pub type BoffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Parity Error Detected\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Per {
    #[doc = "0: `0`"]
    None = 0,
    #[doc = "1: `1`"]
    ErrorDetected = 1,
}
impl From<Per> for bool {
    #[inline(always)]
    fn from(variant: Per) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `PER` reader - Parity Error Detected"]
pub type PerR = crate::BitReader<Per>;
impl PerR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Per {
        match self.bits {
            false => Per::None,
            true => Per::ErrorDetected,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_none(&self) -> bool {
        *self == Per::None
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_error_detected(&self) -> bool {
        *self == Per::ErrorDetected
    }
}
#[doc = "Field `PER` writer - Parity Error Detected"]
pub type PerW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - The LEC field holds a code which indicates the type of the last error to occur on the CAN bus. This field will be cleared to 0 when a message has been transferred (reception or transmission) without error."]
    #[inline(always)]
    pub fn lec(&self) -> LecR {
        LecR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 3 - Transmitted a Message Successfully"]
    #[inline(always)]
    pub fn tx_ok(&self) -> TxOkR {
        TxOkR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Received a Message Successfully"]
    #[inline(always)]
    pub fn rx_ok(&self) -> RxOkR {
        RxOkR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Error Passive"]
    #[inline(always)]
    pub fn epass(&self) -> EpassR {
        EpassR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Warning Status"]
    #[inline(always)]
    pub fn ewarn(&self) -> EwarnR {
        EwarnR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Bus_Off Status"]
    #[inline(always)]
    pub fn boff(&self) -> BoffR {
        BoffR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Parity Error Detected"]
    #[inline(always)]
    pub fn per(&self) -> PerR {
        PerR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - The LEC field holds a code which indicates the type of the last error to occur on the CAN bus. This field will be cleared to 0 when a message has been transferred (reception or transmission) without error."]
    #[inline(always)]
    #[must_use]
    pub fn lec(&mut self) -> LecW<ProtogrpCstsSpec> {
        LecW::new(self, 0)
    }
    #[doc = "Bit 3 - Transmitted a Message Successfully"]
    #[inline(always)]
    #[must_use]
    pub fn tx_ok(&mut self) -> TxOkW<ProtogrpCstsSpec> {
        TxOkW::new(self, 3)
    }
    #[doc = "Bit 4 - Received a Message Successfully"]
    #[inline(always)]
    #[must_use]
    pub fn rx_ok(&mut self) -> RxOkW<ProtogrpCstsSpec> {
        RxOkW::new(self, 4)
    }
    #[doc = "Bit 5 - Error Passive"]
    #[inline(always)]
    #[must_use]
    pub fn epass(&mut self) -> EpassW<ProtogrpCstsSpec> {
        EpassW::new(self, 5)
    }
    #[doc = "Bit 6 - Warning Status"]
    #[inline(always)]
    #[must_use]
    pub fn ewarn(&mut self) -> EwarnW<ProtogrpCstsSpec> {
        EwarnW::new(self, 6)
    }
    #[doc = "Bit 7 - Bus_Off Status"]
    #[inline(always)]
    #[must_use]
    pub fn boff(&mut self) -> BoffW<ProtogrpCstsSpec> {
        BoffW::new(self, 7)
    }
    #[doc = "Bit 8 - Parity Error Detected"]
    #[inline(always)]
    #[must_use]
    pub fn per(&mut self) -> PerW<ProtogrpCstsSpec> {
        PerW::new(self, 8)
    }
}
#[doc = "Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_csts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCstsSpec;
impl crate::RegisterSpec for ProtogrpCstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`protogrp_csts::R`](R) reader structure"]
impl crate::Readable for ProtogrpCstsSpec {}
#[doc = "`reset()` method sets protogrp_CSTS to value 0x07"]
impl crate::Resettable for ProtogrpCstsSpec {
    const RESET_VALUE: u32 = 0x07;
}
