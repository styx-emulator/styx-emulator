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
#[doc = "Register `globgrp_gnptxsts` reader"]
pub type R = crate::R<GlobgrpGnptxstsSpec>;
#[doc = "Register `globgrp_gnptxsts` writer"]
pub type W = crate::W<GlobgrpGnptxstsSpec>;
#[doc = "Field `nptxfspcavail` reader - Indicates the amount of free space available in the Non-periodic TxFIFO.Values are in terms of 32-bit words. 16h0: Non-periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available (where 0 n 32,768) 16h8000: 32,768 words available Others: Reserved"]
pub type NptxfspcavailR = crate::FieldReader<u16>;
#[doc = "Field `nptxfspcavail` writer - Indicates the amount of free space available in the Non-periodic TxFIFO.Values are in terms of 32-bit words. 16h0: Non-periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available (where 0 n 32,768) 16h8000: 32,768 words available Others: Reserved"]
pub type NptxfspcavailW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Indicates the amount of free space available in the Non-periodic Transmit Request Queue. This queue holds both IN and OUT requests in Host mode. Device mode has only IN requests. -Others: Reserved\n\nValue on reset: 8"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Nptxqspcavail {
    #[doc = "0: `0`"]
    Full = 0,
    #[doc = "1: `1`"]
    Que1 = 1,
    #[doc = "2: `10`"]
    Que2 = 2,
    #[doc = "3: `11`"]
    Que3 = 3,
    #[doc = "4: `100`"]
    Que4 = 4,
    #[doc = "5: `101`"]
    Que5 = 5,
    #[doc = "6: `110`"]
    Que6 = 6,
    #[doc = "7: `111`"]
    Que7 = 7,
    #[doc = "8: `1000`"]
    Que8 = 8,
}
impl From<Nptxqspcavail> for u8 {
    #[inline(always)]
    fn from(variant: Nptxqspcavail) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Nptxqspcavail {
    type Ux = u8;
}
#[doc = "Field `nptxqspcavail` reader - Indicates the amount of free space available in the Non-periodic Transmit Request Queue. This queue holds both IN and OUT requests in Host mode. Device mode has only IN requests. -Others: Reserved"]
pub type NptxqspcavailR = crate::FieldReader<Nptxqspcavail>;
impl NptxqspcavailR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Nptxqspcavail> {
        match self.bits {
            0 => Some(Nptxqspcavail::Full),
            1 => Some(Nptxqspcavail::Que1),
            2 => Some(Nptxqspcavail::Que2),
            3 => Some(Nptxqspcavail::Que3),
            4 => Some(Nptxqspcavail::Que4),
            5 => Some(Nptxqspcavail::Que5),
            6 => Some(Nptxqspcavail::Que6),
            7 => Some(Nptxqspcavail::Que7),
            8 => Some(Nptxqspcavail::Que8),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Nptxqspcavail::Full
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_que1(&self) -> bool {
        *self == Nptxqspcavail::Que1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_que2(&self) -> bool {
        *self == Nptxqspcavail::Que2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_que3(&self) -> bool {
        *self == Nptxqspcavail::Que3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_que4(&self) -> bool {
        *self == Nptxqspcavail::Que4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_que5(&self) -> bool {
        *self == Nptxqspcavail::Que5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_que6(&self) -> bool {
        *self == Nptxqspcavail::Que6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_que7(&self) -> bool {
        *self == Nptxqspcavail::Que7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_que8(&self) -> bool {
        *self == Nptxqspcavail::Que8
    }
}
#[doc = "Field `nptxqspcavail` writer - Indicates the amount of free space available in the Non-periodic Transmit Request Queue. This queue holds both IN and OUT requests in Host mode. Device mode has only IN requests. -Others: Reserved"]
pub type NptxqspcavailW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Entry in the Non-periodic Tx Request Queue that is currently being processed by the MAC. -Bits \\[30:27\\]: Channel/endpoint number -Bits \\[26:25\\]: -Bit \\[24\\]: Terminate (last Entry for selected channel endpoint)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Nptxqtop {
    #[doc = "0: `0`"]
    Inouttk = 0,
    #[doc = "1: `1`"]
    Zerotx = 1,
    #[doc = "2: `10`"]
    Pingcsplit = 2,
    #[doc = "3: `11`"]
    Chnhalt = 3,
}
impl From<Nptxqtop> for u8 {
    #[inline(always)]
    fn from(variant: Nptxqtop) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Nptxqtop {
    type Ux = u8;
}
#[doc = "Field `nptxqtop` reader - Entry in the Non-periodic Tx Request Queue that is currently being processed by the MAC. -Bits \\[30:27\\]: Channel/endpoint number -Bits \\[26:25\\]: -Bit \\[24\\]: Terminate (last Entry for selected channel endpoint)"]
pub type NptxqtopR = crate::FieldReader<Nptxqtop>;
impl NptxqtopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Nptxqtop> {
        match self.bits {
            0 => Some(Nptxqtop::Inouttk),
            1 => Some(Nptxqtop::Zerotx),
            2 => Some(Nptxqtop::Pingcsplit),
            3 => Some(Nptxqtop::Chnhalt),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inouttk(&self) -> bool {
        *self == Nptxqtop::Inouttk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_zerotx(&self) -> bool {
        *self == Nptxqtop::Zerotx
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_pingcsplit(&self) -> bool {
        *self == Nptxqtop::Pingcsplit
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_chnhalt(&self) -> bool {
        *self == Nptxqtop::Chnhalt
    }
}
#[doc = "Field `nptxqtop` writer - Entry in the Non-periodic Tx Request Queue that is currently being processed by the MAC. -Bits \\[30:27\\]: Channel/endpoint number -Bits \\[26:25\\]: -Bit \\[24\\]: Terminate (last Entry for selected channel endpoint)"]
pub type NptxqtopW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:15 - Indicates the amount of free space available in the Non-periodic TxFIFO.Values are in terms of 32-bit words. 16h0: Non-periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available (where 0 n 32,768) 16h8000: 32,768 words available Others: Reserved"]
    #[inline(always)]
    pub fn nptxfspcavail(&self) -> NptxfspcavailR {
        NptxfspcavailR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:23 - Indicates the amount of free space available in the Non-periodic Transmit Request Queue. This queue holds both IN and OUT requests in Host mode. Device mode has only IN requests. -Others: Reserved"]
    #[inline(always)]
    pub fn nptxqspcavail(&self) -> NptxqspcavailR {
        NptxqspcavailR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:30 - Entry in the Non-periodic Tx Request Queue that is currently being processed by the MAC. -Bits \\[30:27\\]: Channel/endpoint number -Bits \\[26:25\\]: -Bit \\[24\\]: Terminate (last Entry for selected channel endpoint)"]
    #[inline(always)]
    pub fn nptxqtop(&self) -> NptxqtopR {
        NptxqtopR::new(((self.bits >> 24) & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:15 - Indicates the amount of free space available in the Non-periodic TxFIFO.Values are in terms of 32-bit words. 16h0: Non-periodic TxFIFO is full 16h1: 1 word available 16h2: 2 words available 16hn: n words available (where 0 n 32,768) 16h8000: 32,768 words available Others: Reserved"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfspcavail(&mut self) -> NptxfspcavailW<GlobgrpGnptxstsSpec> {
        NptxfspcavailW::new(self, 0)
    }
    #[doc = "Bits 16:23 - Indicates the amount of free space available in the Non-periodic Transmit Request Queue. This queue holds both IN and OUT requests in Host mode. Device mode has only IN requests. -Others: Reserved"]
    #[inline(always)]
    #[must_use]
    pub fn nptxqspcavail(&mut self) -> NptxqspcavailW<GlobgrpGnptxstsSpec> {
        NptxqspcavailW::new(self, 16)
    }
    #[doc = "Bits 24:30 - Entry in the Non-periodic Tx Request Queue that is currently being processed by the MAC. -Bits \\[30:27\\]: Channel/endpoint number -Bits \\[26:25\\]: -Bit \\[24\\]: Terminate (last Entry for selected channel endpoint)"]
    #[inline(always)]
    #[must_use]
    pub fn nptxqtop(&mut self) -> NptxqtopW<GlobgrpGnptxstsSpec> {
        NptxqtopW::new(self, 24)
    }
}
#[doc = "In Device mode, this register is valid only in Shared FIFO operation. It contains the free space information for the Non-periodic TxFIFO and the Nonperiodic Transmit RequestQueue\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gnptxsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGnptxstsSpec;
impl crate::RegisterSpec for GlobgrpGnptxstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`globgrp_gnptxsts::R`](R) reader structure"]
impl crate::Readable for GlobgrpGnptxstsSpec {}
#[doc = "`reset()` method sets globgrp_gnptxsts to value 0x0008_0400"]
impl crate::Resettable for GlobgrpGnptxstsSpec {
    const RESET_VALUE: u32 = 0x0008_0400;
}
