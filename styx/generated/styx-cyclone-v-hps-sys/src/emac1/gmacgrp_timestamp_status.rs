// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Timestamp_Status` reader"]
pub type R = crate::R<GmacgrpTimestampStatusSpec>;
#[doc = "Register `gmacgrp_Timestamp_Status` writer"]
pub type W = crate::W<GmacgrpTimestampStatusSpec>;
#[doc = "When set, this bit indicates that the seconds value of the timestamp (when supporting version 2 format) has overflowed beyond 32'hFFFF_FFFF.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tssovf {
    #[doc = "0: `0`"]
    Reset = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<Tssovf> for bool {
    #[inline(always)]
    fn from(variant: Tssovf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tssovf` reader - When set, this bit indicates that the seconds value of the timestamp (when supporting version 2 format) has overflowed beyond 32'hFFFF_FFFF."]
pub type TssovfR = crate::BitReader<Tssovf>;
impl TssovfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tssovf {
        match self.bits {
            false => Tssovf::Reset,
            true => Tssovf::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Tssovf::Reset
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == Tssovf::Set
    }
}
#[doc = "Field `tssovf` writer - When set, this bit indicates that the seconds value of the timestamp (when supporting version 2 format) has overflowed beyond 32'hFFFF_FFFF."]
pub type TssovfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit indicates that the value of system time is greater or equal to the value specified in the Register 455 (Target Time Seconds Register) and Register 456 (Target Time Nanoseconds Register).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tstargt {
    #[doc = "0: `0`"]
    Reset = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<Tstargt> for bool {
    #[inline(always)]
    fn from(variant: Tstargt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tstargt` reader - When set, this bit indicates that the value of system time is greater or equal to the value specified in the Register 455 (Target Time Seconds Register) and Register 456 (Target Time Nanoseconds Register)."]
pub type TstargtR = crate::BitReader<Tstargt>;
impl TstargtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tstargt {
        match self.bits {
            false => Tstargt::Reset,
            true => Tstargt::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Tstargt::Reset
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == Tstargt::Set
    }
}
#[doc = "Field `tstargt` writer - When set, this bit indicates that the value of system time is greater or equal to the value specified in the Register 455 (Target Time Seconds Register) and Register 456 (Target Time Nanoseconds Register)."]
pub type TstargtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set high when the auxiliary snapshot is written to the FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auxtstrig {
    #[doc = "0: `0`"]
    Reset = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<Auxtstrig> for bool {
    #[inline(always)]
    fn from(variant: Auxtstrig) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `auxtstrig` reader - This bit is set high when the auxiliary snapshot is written to the FIFO."]
pub type AuxtstrigR = crate::BitReader<Auxtstrig>;
impl AuxtstrigR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Auxtstrig {
        match self.bits {
            false => Auxtstrig::Reset,
            true => Auxtstrig::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Auxtstrig::Reset
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == Auxtstrig::Set
    }
}
#[doc = "Field `auxtstrig` writer - This bit is set high when the auxiliary snapshot is written to the FIFO."]
pub type AuxtstrigW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the target time, being programmed in Target Time Registers, is already elapsed. This bit is cleared when read by the application.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tstrgterr {
    #[doc = "0: `0`"]
    Reset = 0,
    #[doc = "1: `1`"]
    Set = 1,
}
impl From<Tstrgterr> for bool {
    #[inline(always)]
    fn from(variant: Tstrgterr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tstrgterr` reader - This bit is set when the target time, being programmed in Target Time Registers, is already elapsed. This bit is cleared when read by the application."]
pub type TstrgterrR = crate::BitReader<Tstrgterr>;
impl TstrgterrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tstrgterr {
        match self.bits {
            false => Tstrgterr::Reset,
            true => Tstrgterr::Set,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Tstrgterr::Reset
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == Tstrgterr::Set
    }
}
#[doc = "Field `tstrgterr` writer - This bit is set when the target time, being programmed in Target Time Registers, is already elapsed. This bit is cleared when read by the application."]
pub type TstrgterrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `atsstn` reader - These bits identify the Auxiliary trigger inputs for which the timestamp available in the Auxiliary Snapshot Register is applicable. When more than one bit is set at the same time, it means that corresponding auxiliary triggers were sampled at the same clock. These bits are applicable only if the number of Auxiliary snapshots is more than one. One bit is assigned for each trigger as shown in the following list: * Bit 16: Auxiliary trigger 0 * Bit 17: Auxiliary trigger 1 * Bit 18: Auxiliary trigger 2 * Bit 19: Auxiliary trigger 3 The software can read this register to find the triggers that are set when the timestamp is taken."]
pub type AtsstnR = crate::FieldReader;
#[doc = "Field `atsstn` writer - These bits identify the Auxiliary trigger inputs for which the timestamp available in the Auxiliary Snapshot Register is applicable. When more than one bit is set at the same time, it means that corresponding auxiliary triggers were sampled at the same clock. These bits are applicable only if the number of Auxiliary snapshots is more than one. One bit is assigned for each trigger as shown in the following list: * Bit 16: Auxiliary trigger 0 * Bit 17: Auxiliary trigger 1 * Bit 18: Auxiliary trigger 2 * Bit 19: Auxiliary trigger 3 The software can read this register to find the triggers that are set when the timestamp is taken."]
pub type AtsstnW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "This bit is set when the Auxiliary timestamp snapshot FIFO is full and external trigger was set. This indicates that the latest snapshot is not stored in the FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atsstm {
    #[doc = "0: `0`"]
    Notfull = 0,
    #[doc = "1: `1`"]
    Full = 1,
}
impl From<Atsstm> for bool {
    #[inline(always)]
    fn from(variant: Atsstm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `atsstm` reader - This bit is set when the Auxiliary timestamp snapshot FIFO is full and external trigger was set. This indicates that the latest snapshot is not stored in the FIFO."]
pub type AtsstmR = crate::BitReader<Atsstm>;
impl AtsstmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Atsstm {
        match self.bits {
            false => Atsstm::Notfull,
            true => Atsstm::Full,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Atsstm::Notfull
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Atsstm::Full
    }
}
#[doc = "Field `atsstm` writer - This bit is set when the Auxiliary timestamp snapshot FIFO is full and external trigger was set. This indicates that the latest snapshot is not stored in the FIFO."]
pub type AtsstmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `atsns` reader - This field indicates the number of Snapshots available in the FIFO. A value of 16 (equal to the depth of the FIFO) indicates that the Auxiliary Snapshot FIFO is full. These bits are cleared (to 00000) when the Auxiliary snapshot FIFO clear bit is set."]
pub type AtsnsR = crate::FieldReader;
#[doc = "Field `atsns` writer - This field indicates the number of Snapshots available in the FIFO. A value of 16 (equal to the depth of the FIFO) indicates that the Auxiliary Snapshot FIFO is full. These bits are cleared (to 00000) when the Auxiliary snapshot FIFO clear bit is set."]
pub type AtsnsW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bit 0 - When set, this bit indicates that the seconds value of the timestamp (when supporting version 2 format) has overflowed beyond 32'hFFFF_FFFF."]
    #[inline(always)]
    pub fn tssovf(&self) -> TssovfR {
        TssovfR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates that the value of system time is greater or equal to the value specified in the Register 455 (Target Time Seconds Register) and Register 456 (Target Time Nanoseconds Register)."]
    #[inline(always)]
    pub fn tstargt(&self) -> TstargtR {
        TstargtR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit is set high when the auxiliary snapshot is written to the FIFO."]
    #[inline(always)]
    pub fn auxtstrig(&self) -> AuxtstrigR {
        AuxtstrigR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is set when the target time, being programmed in Target Time Registers, is already elapsed. This bit is cleared when read by the application."]
    #[inline(always)]
    pub fn tstrgterr(&self) -> TstrgterrR {
        TstrgterrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 16:19 - These bits identify the Auxiliary trigger inputs for which the timestamp available in the Auxiliary Snapshot Register is applicable. When more than one bit is set at the same time, it means that corresponding auxiliary triggers were sampled at the same clock. These bits are applicable only if the number of Auxiliary snapshots is more than one. One bit is assigned for each trigger as shown in the following list: * Bit 16: Auxiliary trigger 0 * Bit 17: Auxiliary trigger 1 * Bit 18: Auxiliary trigger 2 * Bit 19: Auxiliary trigger 3 The software can read this register to find the triggers that are set when the timestamp is taken."]
    #[inline(always)]
    pub fn atsstn(&self) -> AtsstnR {
        AtsstnR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bit 24 - This bit is set when the Auxiliary timestamp snapshot FIFO is full and external trigger was set. This indicates that the latest snapshot is not stored in the FIFO."]
    #[inline(always)]
    pub fn atsstm(&self) -> AtsstmR {
        AtsstmR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bits 25:29 - This field indicates the number of Snapshots available in the FIFO. A value of 16 (equal to the depth of the FIFO) indicates that the Auxiliary Snapshot FIFO is full. These bits are cleared (to 00000) when the Auxiliary snapshot FIFO clear bit is set."]
    #[inline(always)]
    pub fn atsns(&self) -> AtsnsR {
        AtsnsR::new(((self.bits >> 25) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - When set, this bit indicates that the seconds value of the timestamp (when supporting version 2 format) has overflowed beyond 32'hFFFF_FFFF."]
    #[inline(always)]
    #[must_use]
    pub fn tssovf(&mut self) -> TssovfW<GmacgrpTimestampStatusSpec> {
        TssovfW::new(self, 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates that the value of system time is greater or equal to the value specified in the Register 455 (Target Time Seconds Register) and Register 456 (Target Time Nanoseconds Register)."]
    #[inline(always)]
    #[must_use]
    pub fn tstargt(&mut self) -> TstargtW<GmacgrpTimestampStatusSpec> {
        TstargtW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit is set high when the auxiliary snapshot is written to the FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn auxtstrig(&mut self) -> AuxtstrigW<GmacgrpTimestampStatusSpec> {
        AuxtstrigW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is set when the target time, being programmed in Target Time Registers, is already elapsed. This bit is cleared when read by the application."]
    #[inline(always)]
    #[must_use]
    pub fn tstrgterr(&mut self) -> TstrgterrW<GmacgrpTimestampStatusSpec> {
        TstrgterrW::new(self, 3)
    }
    #[doc = "Bits 16:19 - These bits identify the Auxiliary trigger inputs for which the timestamp available in the Auxiliary Snapshot Register is applicable. When more than one bit is set at the same time, it means that corresponding auxiliary triggers were sampled at the same clock. These bits are applicable only if the number of Auxiliary snapshots is more than one. One bit is assigned for each trigger as shown in the following list: * Bit 16: Auxiliary trigger 0 * Bit 17: Auxiliary trigger 1 * Bit 18: Auxiliary trigger 2 * Bit 19: Auxiliary trigger 3 The software can read this register to find the triggers that are set when the timestamp is taken."]
    #[inline(always)]
    #[must_use]
    pub fn atsstn(&mut self) -> AtsstnW<GmacgrpTimestampStatusSpec> {
        AtsstnW::new(self, 16)
    }
    #[doc = "Bit 24 - This bit is set when the Auxiliary timestamp snapshot FIFO is full and external trigger was set. This indicates that the latest snapshot is not stored in the FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn atsstm(&mut self) -> AtsstmW<GmacgrpTimestampStatusSpec> {
        AtsstmW::new(self, 24)
    }
    #[doc = "Bits 25:29 - This field indicates the number of Snapshots available in the FIFO. A value of 16 (equal to the depth of the FIFO) indicates that the Auxiliary Snapshot FIFO is full. These bits are cleared (to 00000) when the Auxiliary snapshot FIFO clear bit is set."]
    #[inline(always)]
    #[must_use]
    pub fn atsns(&mut self) -> AtsnsW<GmacgrpTimestampStatusSpec> {
        AtsnsW::new(self, 25)
    }
}
#[doc = "Timestamp status. All bits except Bits\\[27:25\\]
get cleared when the host reads this register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_timestamp_status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTimestampStatusSpec;
impl crate::RegisterSpec for GmacgrpTimestampStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 1832u64;
}
#[doc = "`read()` method returns [`gmacgrp_timestamp_status::R`](R) reader structure"]
impl crate::Readable for GmacgrpTimestampStatusSpec {}
#[doc = "`reset()` method sets gmacgrp_Timestamp_Status to value 0"]
impl crate::Resettable for GmacgrpTimestampStatusSpec {
    const RESET_VALUE: u32 = 0;
}
