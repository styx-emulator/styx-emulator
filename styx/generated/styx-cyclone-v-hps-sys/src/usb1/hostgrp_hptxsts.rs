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
#[doc = "Register `hostgrp_hptxsts` reader"]
pub type R = crate::R<HostgrpHptxstsSpec>;
#[doc = "Register `hostgrp_hptxsts` writer"]
pub type W = crate::W<HostgrpHptxstsSpec>;
#[doc = "Field `ptxfspcavail` reader - Indicates the number of free locations available to be written to in the Periodic TxFIFO. Values are in terms of 32-bit words 16h0: Periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available where n is 0 to 8192"]
pub type PtxfspcavailR = crate::FieldReader<u16>;
#[doc = "Field `ptxfspcavail` writer - Indicates the number of free locations available to be written to in the Periodic TxFIFO. Values are in terms of 32-bit words 16h0: Periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available where n is 0 to 8192"]
pub type PtxfspcavailW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Indicates the number of free locations available to be written in the Periodic Transmit Request Queue. This queue holds both IN and OUT requests. Others: Reserved\n\nValue on reset: 16"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ptxqspcavail {
    #[doc = "0: `0`"]
    Full = 0,
    #[doc = "1: `1`"]
    Free1 = 1,
    #[doc = "2: `10`"]
    Free2 = 2,
    #[doc = "3: `11`"]
    Free3 = 3,
    #[doc = "4: `100`"]
    Free4 = 4,
    #[doc = "5: `101`"]
    Free5 = 5,
    #[doc = "6: `110`"]
    Free6 = 6,
    #[doc = "7: `111`"]
    Free7 = 7,
    #[doc = "8: `1000`"]
    Free8 = 8,
}
impl From<Ptxqspcavail> for u8 {
    #[inline(always)]
    fn from(variant: Ptxqspcavail) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ptxqspcavail {
    type Ux = u8;
}
#[doc = "Field `ptxqspcavail` reader - Indicates the number of free locations available to be written in the Periodic Transmit Request Queue. This queue holds both IN and OUT requests. Others: Reserved"]
pub type PtxqspcavailR = crate::FieldReader<Ptxqspcavail>;
impl PtxqspcavailR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ptxqspcavail> {
        match self.bits {
            0 => Some(Ptxqspcavail::Full),
            1 => Some(Ptxqspcavail::Free1),
            2 => Some(Ptxqspcavail::Free2),
            3 => Some(Ptxqspcavail::Free3),
            4 => Some(Ptxqspcavail::Free4),
            5 => Some(Ptxqspcavail::Free5),
            6 => Some(Ptxqspcavail::Free6),
            7 => Some(Ptxqspcavail::Free7),
            8 => Some(Ptxqspcavail::Free8),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Ptxqspcavail::Full
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_free1(&self) -> bool {
        *self == Ptxqspcavail::Free1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_free2(&self) -> bool {
        *self == Ptxqspcavail::Free2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_free3(&self) -> bool {
        *self == Ptxqspcavail::Free3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_free4(&self) -> bool {
        *self == Ptxqspcavail::Free4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_free5(&self) -> bool {
        *self == Ptxqspcavail::Free5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_free6(&self) -> bool {
        *self == Ptxqspcavail::Free6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_free7(&self) -> bool {
        *self == Ptxqspcavail::Free7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_free8(&self) -> bool {
        *self == Ptxqspcavail::Free8
    }
}
#[doc = "Field `ptxqspcavail` writer - Indicates the number of free locations available to be written in the Periodic Transmit Request Queue. This queue holds both IN and OUT requests. Others: Reserved"]
pub type PtxqspcavailW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Terminate last entry for selected channel/endpoint.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Term {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Term> for bool {
    #[inline(always)]
    fn from(variant: Term) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `term` reader - Terminate last entry for selected channel/endpoint."]
pub type TermR = crate::BitReader<Term>;
impl TermR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Term {
        match self.bits {
            false => Term::Inactive,
            true => Term::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Term::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Term::Active
    }
}
#[doc = "Field `term` writer - Terminate last entry for selected channel/endpoint."]
pub type TermW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This indicates the Entry in the Periodic Tx Request Queue that is currently being processes by the MAC.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    #[doc = "0: `0`"]
    Inout = 0,
    #[doc = "1: `1`"]
    Zerolngth = 1,
    #[doc = "2: `10`"]
    Csplit = 2,
    #[doc = "3: `11`"]
    Disable = 3,
}
impl From<Type> for u8 {
    #[inline(always)]
    fn from(variant: Type) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Type {
    type Ux = u8;
}
#[doc = "Field `type` reader - This indicates the Entry in the Periodic Tx Request Queue that is currently being processes by the MAC."]
pub type TypeR = crate::FieldReader<Type>;
impl TypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Type {
        match self.bits {
            0 => Type::Inout,
            1 => Type::Zerolngth,
            2 => Type::Csplit,
            3 => Type::Disable,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inout(&self) -> bool {
        *self == Type::Inout
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_zerolngth(&self) -> bool {
        *self == Type::Zerolngth
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_csplit(&self) -> bool {
        *self == Type::Csplit
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Type::Disable
    }
}
#[doc = "Field `type` writer - This indicates the Entry in the Periodic Tx Request Queue that is currently being processes by the MAC."]
pub type TypeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "This indicates the channel endpoint number that is currently being processes by the MAC.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Chanendpt {
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
impl From<Chanendpt> for u8 {
    #[inline(always)]
    fn from(variant: Chanendpt) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Chanendpt {
    type Ux = u8;
}
#[doc = "Field `chanendpt` reader - This indicates the channel endpoint number that is currently being processes by the MAC."]
pub type ChanendptR = crate::FieldReader<Chanendpt>;
impl ChanendptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chanendpt {
        match self.bits {
            0 => Chanendpt::Endpt0,
            1 => Chanendpt::Endpt1,
            2 => Chanendpt::Endpt2,
            3 => Chanendpt::Endpt3,
            4 => Chanendpt::Endpt4,
            5 => Chanendpt::Endpt5,
            6 => Chanendpt::Endpt6,
            7 => Chanendpt::Endpt7,
            8 => Chanendpt::Endpt8,
            9 => Chanendpt::Endpt9,
            10 => Chanendpt::Endpt10,
            11 => Chanendpt::Endpt11,
            12 => Chanendpt::Endpt12,
            13 => Chanendpt::Endpt13,
            14 => Chanendpt::Endpt14,
            15 => Chanendpt::Endpt15,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_endpt0(&self) -> bool {
        *self == Chanendpt::Endpt0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_endpt1(&self) -> bool {
        *self == Chanendpt::Endpt1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_endpt2(&self) -> bool {
        *self == Chanendpt::Endpt2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_endpt3(&self) -> bool {
        *self == Chanendpt::Endpt3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_endpt4(&self) -> bool {
        *self == Chanendpt::Endpt4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_endpt5(&self) -> bool {
        *self == Chanendpt::Endpt5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_endpt6(&self) -> bool {
        *self == Chanendpt::Endpt6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_endpt7(&self) -> bool {
        *self == Chanendpt::Endpt7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_endpt8(&self) -> bool {
        *self == Chanendpt::Endpt8
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_endpt9(&self) -> bool {
        *self == Chanendpt::Endpt9
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_endpt10(&self) -> bool {
        *self == Chanendpt::Endpt10
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_endpt11(&self) -> bool {
        *self == Chanendpt::Endpt11
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_endpt12(&self) -> bool {
        *self == Chanendpt::Endpt12
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_endpt13(&self) -> bool {
        *self == Chanendpt::Endpt13
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_endpt14(&self) -> bool {
        *self == Chanendpt::Endpt14
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_endpt15(&self) -> bool {
        *self == Chanendpt::Endpt15
    }
}
#[doc = "Field `chanendpt` writer - This indicates the channel endpoint number that is currently being processes by the MAC."]
pub type ChanendptW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "This indicates the odd/even micro frame that is currently being processes by the MAC.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oddevnmframe {
    #[doc = "0: `0`"]
    Even = 0,
    #[doc = "1: `1`"]
    Odd = 1,
}
impl From<Oddevnmframe> for bool {
    #[inline(always)]
    fn from(variant: Oddevnmframe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `oddevnmframe` reader - This indicates the odd/even micro frame that is currently being processes by the MAC."]
pub type OddevnmframeR = crate::BitReader<Oddevnmframe>;
impl OddevnmframeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Oddevnmframe {
        match self.bits {
            false => Oddevnmframe::Even,
            true => Oddevnmframe::Odd,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_even(&self) -> bool {
        *self == Oddevnmframe::Even
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_odd(&self) -> bool {
        *self == Oddevnmframe::Odd
    }
}
#[doc = "Field `oddevnmframe` writer - This indicates the odd/even micro frame that is currently being processes by the MAC."]
pub type OddevnmframeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - Indicates the number of free locations available to be written to in the Periodic TxFIFO. Values are in terms of 32-bit words 16h0: Periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available where n is 0 to 8192"]
    #[inline(always)]
    pub fn ptxfspcavail(&self) -> PtxfspcavailR {
        PtxfspcavailR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:23 - Indicates the number of free locations available to be written in the Periodic Transmit Request Queue. This queue holds both IN and OUT requests. Others: Reserved"]
    #[inline(always)]
    pub fn ptxqspcavail(&self) -> PtxqspcavailR {
        PtxqspcavailR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bit 24 - Terminate last entry for selected channel/endpoint."]
    #[inline(always)]
    pub fn term(&self) -> TermR {
        TermR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bits 25:26 - This indicates the Entry in the Periodic Tx Request Queue that is currently being processes by the MAC."]
    #[inline(always)]
    pub fn type_(&self) -> TypeR {
        TypeR::new(((self.bits >> 25) & 3) as u8)
    }
    #[doc = "Bits 27:30 - This indicates the channel endpoint number that is currently being processes by the MAC."]
    #[inline(always)]
    pub fn chanendpt(&self) -> ChanendptR {
        ChanendptR::new(((self.bits >> 27) & 0x0f) as u8)
    }
    #[doc = "Bit 31 - This indicates the odd/even micro frame that is currently being processes by the MAC."]
    #[inline(always)]
    pub fn oddevnmframe(&self) -> OddevnmframeR {
        OddevnmframeR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - Indicates the number of free locations available to be written to in the Periodic TxFIFO. Values are in terms of 32-bit words 16h0: Periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available where n is 0 to 8192"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfspcavail(&mut self) -> PtxfspcavailW<HostgrpHptxstsSpec> {
        PtxfspcavailW::new(self, 0)
    }
    #[doc = "Bits 16:23 - Indicates the number of free locations available to be written in the Periodic Transmit Request Queue. This queue holds both IN and OUT requests. Others: Reserved"]
    #[inline(always)]
    #[must_use]
    pub fn ptxqspcavail(&mut self) -> PtxqspcavailW<HostgrpHptxstsSpec> {
        PtxqspcavailW::new(self, 16)
    }
    #[doc = "Bit 24 - Terminate last entry for selected channel/endpoint."]
    #[inline(always)]
    #[must_use]
    pub fn term(&mut self) -> TermW<HostgrpHptxstsSpec> {
        TermW::new(self, 24)
    }
    #[doc = "Bits 25:26 - This indicates the Entry in the Periodic Tx Request Queue that is currently being processes by the MAC."]
    #[inline(always)]
    #[must_use]
    pub fn type_(&mut self) -> TypeW<HostgrpHptxstsSpec> {
        TypeW::new(self, 25)
    }
    #[doc = "Bits 27:30 - This indicates the channel endpoint number that is currently being processes by the MAC."]
    #[inline(always)]
    #[must_use]
    pub fn chanendpt(&mut self) -> ChanendptW<HostgrpHptxstsSpec> {
        ChanendptW::new(self, 27)
    }
    #[doc = "Bit 31 - This indicates the odd/even micro frame that is currently being processes by the MAC."]
    #[inline(always)]
    #[must_use]
    pub fn oddevnmframe(&mut self) -> OddevnmframeW<HostgrpHptxstsSpec> {
        OddevnmframeW::new(self, 31)
    }
}
#[doc = "This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hptxsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHptxstsSpec;
impl crate::RegisterSpec for HostgrpHptxstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1040u64;
}
#[doc = "`read()` method returns [`hostgrp_hptxsts::R`](R) reader structure"]
impl crate::Readable for HostgrpHptxstsSpec {}
#[doc = "`reset()` method sets hostgrp_hptxsts to value 0x0010_2000"]
impl crate::Resettable for HostgrpHptxstsSpec {
    const RESET_VALUE: u32 = 0x0010_2000;
}
