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
#[doc = "Register `MSR` reader"]
pub type R = crate::R<MsrSpec>;
#[doc = "Register `MSR` writer"]
pub type W = crate::W<MsrSpec>;
#[doc = "Field `INAK` reader - INAK"]
pub type InakR = crate::BitReader;
#[doc = "Field `INAK` writer - INAK"]
pub type InakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SLAK` reader - SLAK"]
pub type SlakR = crate::BitReader;
#[doc = "Field `SLAK` writer - SLAK"]
pub type SlakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERRI` reader - ERRI"]
pub type ErriR = crate::BitReader;
#[doc = "Field `ERRI` writer - ERRI"]
pub type ErriW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WKUI` reader - WKUI"]
pub type WkuiR = crate::BitReader;
#[doc = "Field `WKUI` writer - WKUI"]
pub type WkuiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SLAKI` reader - SLAKI"]
pub type SlakiR = crate::BitReader;
#[doc = "Field `SLAKI` writer - SLAKI"]
pub type SlakiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXM` reader - TXM"]
pub type TxmR = crate::BitReader;
#[doc = "Field `TXM` writer - TXM"]
pub type TxmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXM` reader - RXM"]
pub type RxmR = crate::BitReader;
#[doc = "Field `RXM` writer - RXM"]
pub type RxmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAMP` reader - SAMP"]
pub type SampR = crate::BitReader;
#[doc = "Field `SAMP` writer - SAMP"]
pub type SampW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RX` reader - RX"]
pub type RxR = crate::BitReader;
#[doc = "Field `RX` writer - RX"]
pub type RxW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - INAK"]
    #[inline(always)]
    pub fn inak(&self) -> InakR {
        InakR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - SLAK"]
    #[inline(always)]
    pub fn slak(&self) -> SlakR {
        SlakR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - ERRI"]
    #[inline(always)]
    pub fn erri(&self) -> ErriR {
        ErriR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - WKUI"]
    #[inline(always)]
    pub fn wkui(&self) -> WkuiR {
        WkuiR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - SLAKI"]
    #[inline(always)]
    pub fn slaki(&self) -> SlakiR {
        SlakiR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 8 - TXM"]
    #[inline(always)]
    pub fn txm(&self) -> TxmR {
        TxmR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - RXM"]
    #[inline(always)]
    pub fn rxm(&self) -> RxmR {
        RxmR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - SAMP"]
    #[inline(always)]
    pub fn samp(&self) -> SampR {
        SampR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - RX"]
    #[inline(always)]
    pub fn rx(&self) -> RxR {
        RxR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - INAK"]
    #[inline(always)]
    #[must_use]
    pub fn inak(&mut self) -> InakW<MsrSpec> {
        InakW::new(self, 0)
    }
    #[doc = "Bit 1 - SLAK"]
    #[inline(always)]
    #[must_use]
    pub fn slak(&mut self) -> SlakW<MsrSpec> {
        SlakW::new(self, 1)
    }
    #[doc = "Bit 2 - ERRI"]
    #[inline(always)]
    #[must_use]
    pub fn erri(&mut self) -> ErriW<MsrSpec> {
        ErriW::new(self, 2)
    }
    #[doc = "Bit 3 - WKUI"]
    #[inline(always)]
    #[must_use]
    pub fn wkui(&mut self) -> WkuiW<MsrSpec> {
        WkuiW::new(self, 3)
    }
    #[doc = "Bit 4 - SLAKI"]
    #[inline(always)]
    #[must_use]
    pub fn slaki(&mut self) -> SlakiW<MsrSpec> {
        SlakiW::new(self, 4)
    }
    #[doc = "Bit 8 - TXM"]
    #[inline(always)]
    #[must_use]
    pub fn txm(&mut self) -> TxmW<MsrSpec> {
        TxmW::new(self, 8)
    }
    #[doc = "Bit 9 - RXM"]
    #[inline(always)]
    #[must_use]
    pub fn rxm(&mut self) -> RxmW<MsrSpec> {
        RxmW::new(self, 9)
    }
    #[doc = "Bit 10 - SAMP"]
    #[inline(always)]
    #[must_use]
    pub fn samp(&mut self) -> SampW<MsrSpec> {
        SampW::new(self, 10)
    }
    #[doc = "Bit 11 - RX"]
    #[inline(always)]
    #[must_use]
    pub fn rx(&mut self) -> RxW<MsrSpec> {
        RxW::new(self, 11)
    }
}
#[doc = "master status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsrSpec;
impl crate::RegisterSpec for MsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`msr::R`](R) reader structure"]
impl crate::Readable for MsrSpec {}
#[doc = "`write(|w| ..)` method takes [`msr::W`](W) writer structure"]
impl crate::Writable for MsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MSR to value 0x0c02"]
impl crate::Resettable for MsrSpec {
    const RESET_VALUE: u32 = 0x0c02;
}
