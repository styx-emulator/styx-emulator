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
#[doc = "Register `usr` reader"]
pub type R = crate::R<UsrSpec>;
#[doc = "Register `usr` writer"]
pub type W = crate::W<UsrSpec>;
#[doc = "This Bit is used to indicate that the transmit FIFO in not full. This bit is cleared when the Tx FIFO is full.\n\nValue on reset: 1"]
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
#[doc = "Field `tfnf` reader - This Bit is used to indicate that the transmit FIFO in not full. This bit is cleared when the Tx FIFO is full."]
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
#[doc = "Field `tfnf` writer - This Bit is used to indicate that the transmit FIFO in not full. This bit is cleared when the Tx FIFO is full."]
pub type TfnfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate that the transmit FIFO is completely empty. This bit is cleared when the Tx FIFO is no longer empty.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tfe {
    #[doc = "0: `0`"]
    Notempty = 0,
    #[doc = "1: `1`"]
    Empty = 1,
}
impl From<Tfe> for bool {
    #[inline(always)]
    fn from(variant: Tfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tfe` reader - This is used to indicate that the transmit FIFO is completely empty. This bit is cleared when the Tx FIFO is no longer empty."]
pub type TfeR = crate::BitReader<Tfe>;
impl TfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tfe {
        match self.bits {
            false => Tfe::Notempty,
            true => Tfe::Empty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notempty(&self) -> bool {
        *self == Tfe::Notempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Tfe::Empty
    }
}
#[doc = "Field `tfe` writer - This is used to indicate that the transmit FIFO is completely empty. This bit is cleared when the Tx FIFO is no longer empty."]
pub type TfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This Bit is used to indicate that the receive FIFO contains one or more entries. This bit is cleared when the Rx FIFO is empty.\n\nValue on reset: 0"]
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
#[doc = "Field `rfne` reader - This Bit is used to indicate that the receive FIFO contains one or more entries. This bit is cleared when the Rx FIFO is empty."]
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
#[doc = "Field `rfne` writer - This Bit is used to indicate that the receive FIFO contains one or more entries. This bit is cleared when the Rx FIFO is empty."]
pub type RfneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This Bit is used to indicate that the receive FIFO is completely full. This bit is cleared when the Rx FIFO is no longer full.\n\nValue on reset: 0"]
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
#[doc = "Field `rff` reader - This Bit is used to indicate that the receive FIFO is completely full. This bit is cleared when the Rx FIFO is no longer full."]
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
#[doc = "Field `rff` writer - This Bit is used to indicate that the receive FIFO is completely full. This bit is cleared when the Rx FIFO is no longer full."]
pub type RffW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - This Bit is used to indicate that the transmit FIFO in not full. This bit is cleared when the Tx FIFO is full."]
    #[inline(always)]
    pub fn tfnf(&self) -> TfnfR {
        TfnfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This is used to indicate that the transmit FIFO is completely empty. This bit is cleared when the Tx FIFO is no longer empty."]
    #[inline(always)]
    pub fn tfe(&self) -> TfeR {
        TfeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This Bit is used to indicate that the receive FIFO contains one or more entries. This bit is cleared when the Rx FIFO is empty."]
    #[inline(always)]
    pub fn rfne(&self) -> RfneR {
        RfneR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This Bit is used to indicate that the receive FIFO is completely full. This bit is cleared when the Rx FIFO is no longer full."]
    #[inline(always)]
    pub fn rff(&self) -> RffR {
        RffR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - This Bit is used to indicate that the transmit FIFO in not full. This bit is cleared when the Tx FIFO is full."]
    #[inline(always)]
    #[must_use]
    pub fn tfnf(&mut self) -> TfnfW<UsrSpec> {
        TfnfW::new(self, 1)
    }
    #[doc = "Bit 2 - This is used to indicate that the transmit FIFO is completely empty. This bit is cleared when the Tx FIFO is no longer empty."]
    #[inline(always)]
    #[must_use]
    pub fn tfe(&mut self) -> TfeW<UsrSpec> {
        TfeW::new(self, 2)
    }
    #[doc = "Bit 3 - This Bit is used to indicate that the receive FIFO contains one or more entries. This bit is cleared when the Rx FIFO is empty."]
    #[inline(always)]
    #[must_use]
    pub fn rfne(&mut self) -> RfneW<UsrSpec> {
        RfneW::new(self, 3)
    }
    #[doc = "Bit 4 - This Bit is used to indicate that the receive FIFO is completely full. This bit is cleared when the Rx FIFO is no longer full."]
    #[inline(always)]
    #[must_use]
    pub fn rff(&mut self) -> RffW<UsrSpec> {
        RffW::new(self, 4)
    }
}
#[doc = "Status of FIFO Operations.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`usr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct UsrSpec;
impl crate::RegisterSpec for UsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 124u64;
}
#[doc = "`read()` method returns [`usr::R`](R) reader structure"]
impl crate::Readable for UsrSpec {}
#[doc = "`reset()` method sets usr to value 0x06"]
impl crate::Resettable for UsrSpec {
    const RESET_VALUE: u32 = 0x06;
}
