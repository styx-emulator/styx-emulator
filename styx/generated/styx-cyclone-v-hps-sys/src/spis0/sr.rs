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
#[doc = "Register `sr` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `sr` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Reports the status of a serial transfer\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Busy {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Busy> for bool {
    #[inline(always)]
    fn from(variant: Busy) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `busy` reader - Reports the status of a serial transfer"]
pub type BusyR = crate::BitReader<Busy>;
impl BusyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Busy {
        match self.bits {
            false => Busy::Inactive,
            true => Busy::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Busy::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Busy::Active
    }
}
#[doc = "Field `busy` writer - Reports the status of a serial transfer"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Reports the status of the transmit FIFO.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tfnf {
    #[doc = "0: `0`"]
    Full = 0,
    #[doc = "1: `1`"]
    Notfull = 1,
}
impl From<Tfnf> for bool {
    #[inline(always)]
    fn from(variant: Tfnf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tfnf` reader - Reports the status of the transmit FIFO."]
pub type TfnfR = crate::BitReader<Tfnf>;
impl TfnfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tfnf {
        match self.bits {
            false => Tfnf::Full,
            true => Tfnf::Notfull,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Tfnf::Full
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Tfnf::Notfull
    }
}
#[doc = "Field `tfnf` writer - Reports the status of the transmit FIFO."]
pub type TfnfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Reports the status of transmit FIFO empty. This bit field does not request an interrupt.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tfe {
    #[doc = "1: `1`"]
    Empty = 1,
    #[doc = "0: `0`"]
    Notempty = 0,
}
impl From<Tfe> for bool {
    #[inline(always)]
    fn from(variant: Tfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tfe` reader - Reports the status of transmit FIFO empty. This bit field does not request an interrupt."]
pub type TfeR = crate::BitReader<Tfe>;
impl TfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tfe {
        match self.bits {
            true => Tfe::Empty,
            false => Tfe::Notempty,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Tfe::Empty
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notempty(&self) -> bool {
        *self == Tfe::Notempty
    }
}
#[doc = "Field `tfe` writer - Reports the status of transmit FIFO empty. This bit field does not request an interrupt."]
pub type TfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Reports the status of receive FIFO empty.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rfne {
    #[doc = "0: `0`"]
    Empty = 0,
    #[doc = "1: `1`"]
    Notempty = 1,
}
impl From<Rfne> for bool {
    #[inline(always)]
    fn from(variant: Rfne) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rfne` reader - Reports the status of receive FIFO empty."]
pub type RfneR = crate::BitReader<Rfne>;
impl RfneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rfne {
        match self.bits {
            false => Rfne::Empty,
            true => Rfne::Notempty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Rfne::Empty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notempty(&self) -> bool {
        *self == Rfne::Notempty
    }
}
#[doc = "Field `rfne` writer - Reports the status of receive FIFO empty."]
pub type RfneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Reports the status of receive FIFO Full\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rff {
    #[doc = "0: `0`"]
    Notfull = 0,
    #[doc = "1: `1`"]
    Full = 1,
}
impl From<Rff> for bool {
    #[inline(always)]
    fn from(variant: Rff) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rff` reader - Reports the status of receive FIFO Full"]
pub type RffR = crate::BitReader<Rff>;
impl RffR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rff {
        match self.bits {
            false => Rff::Notfull,
            true => Rff::Full,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Rff::Notfull
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Rff::Full
    }
}
#[doc = "Field `rff` writer - Reports the status of receive FIFO Full"]
pub type RffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Data from the previous transmission is resent on the txd line. This bit is cleared when read.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txe {
    #[doc = "0: `0`"]
    Noerror = 0,
    #[doc = "1: `1`"]
    Error = 1,
}
impl From<Txe> for bool {
    #[inline(always)]
    fn from(variant: Txe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txe` reader - Data from the previous transmission is resent on the txd line. This bit is cleared when read."]
pub type TxeR = crate::BitReader<Txe>;
impl TxeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txe {
        match self.bits {
            false => Txe::Noerror,
            true => Txe::Error,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noerror(&self) -> bool {
        *self == Txe::Noerror
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_error(&self) -> bool {
        *self == Txe::Error
    }
}
#[doc = "Field `txe` writer - Data from the previous transmission is resent on the txd line. This bit is cleared when read."]
pub type TxeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Reports the status of a serial transfer"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Reports the status of the transmit FIFO."]
    #[inline(always)]
    pub fn tfnf(&self) -> TfnfR {
        TfnfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Reports the status of transmit FIFO empty. This bit field does not request an interrupt."]
    #[inline(always)]
    pub fn tfe(&self) -> TfeR {
        TfeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Reports the status of receive FIFO empty."]
    #[inline(always)]
    pub fn rfne(&self) -> RfneR {
        RfneR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Reports the status of receive FIFO Full"]
    #[inline(always)]
    pub fn rff(&self) -> RffR {
        RffR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Data from the previous transmission is resent on the txd line. This bit is cleared when read."]
    #[inline(always)]
    pub fn txe(&self) -> TxeR {
        TxeR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Reports the status of a serial transfer"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<SrSpec> {
        BusyW::new(self, 0)
    }
    #[doc = "Bit 1 - Reports the status of the transmit FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn tfnf(&mut self) -> TfnfW<SrSpec> {
        TfnfW::new(self, 1)
    }
    #[doc = "Bit 2 - Reports the status of transmit FIFO empty. This bit field does not request an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn tfe(&mut self) -> TfeW<SrSpec> {
        TfeW::new(self, 2)
    }
    #[doc = "Bit 3 - Reports the status of receive FIFO empty."]
    #[inline(always)]
    #[must_use]
    pub fn rfne(&mut self) -> RfneW<SrSpec> {
        RfneW::new(self, 3)
    }
    #[doc = "Bit 4 - Reports the status of receive FIFO Full"]
    #[inline(always)]
    #[must_use]
    pub fn rff(&mut self) -> RffW<SrSpec> {
        RffW::new(self, 4)
    }
    #[doc = "Bit 5 - Data from the previous transmission is resent on the txd line. This bit is cleared when read."]
    #[inline(always)]
    #[must_use]
    pub fn txe(&mut self) -> TxeW<SrSpec> {
        TxeW::new(self, 5)
    }
}
#[doc = "Reports FIFO transfer status, and any transmission/reception errors that may have occurred. The status register may be read at any time. None of the bits in this register request an interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`reset()` method sets sr to value 0x06"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0x06;
}
