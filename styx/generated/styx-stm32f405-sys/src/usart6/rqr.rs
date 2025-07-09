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
#[doc = "Register `RQR` reader"]
pub type R = crate::R<RqrSpec>;
#[doc = "Register `RQR` writer"]
pub type W = crate::W<RqrSpec>;
#[doc = "Field `ABRRQ` reader - Auto baud rate request"]
pub type AbrrqR = crate::BitReader;
#[doc = "Field `ABRRQ` writer - Auto baud rate request"]
pub type AbrrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBKRQ` reader - Send break request"]
pub type SbkrqR = crate::BitReader;
#[doc = "Field `SBKRQ` writer - Send break request"]
pub type SbkrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMRQ` reader - Mute mode request"]
pub type MmrqR = crate::BitReader;
#[doc = "Field `MMRQ` writer - Mute mode request"]
pub type MmrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFRQ` reader - Receive data flush request"]
pub type RxfrqR = crate::BitReader;
#[doc = "Field `RXFRQ` writer - Receive data flush request"]
pub type RxfrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFRQ` reader - Transmit data flush request"]
pub type TxfrqR = crate::BitReader;
#[doc = "Field `TXFRQ` writer - Transmit data flush request"]
pub type TxfrqW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Auto baud rate request"]
    #[inline(always)]
    pub fn abrrq(&self) -> AbrrqR {
        AbrrqR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Send break request"]
    #[inline(always)]
    pub fn sbkrq(&self) -> SbkrqR {
        SbkrqR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Mute mode request"]
    #[inline(always)]
    pub fn mmrq(&self) -> MmrqR {
        MmrqR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Receive data flush request"]
    #[inline(always)]
    pub fn rxfrq(&self) -> RxfrqR {
        RxfrqR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Transmit data flush request"]
    #[inline(always)]
    pub fn txfrq(&self) -> TxfrqR {
        TxfrqR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Auto baud rate request"]
    #[inline(always)]
    #[must_use]
    pub fn abrrq(&mut self) -> AbrrqW<RqrSpec> {
        AbrrqW::new(self, 0)
    }
    #[doc = "Bit 1 - Send break request"]
    #[inline(always)]
    #[must_use]
    pub fn sbkrq(&mut self) -> SbkrqW<RqrSpec> {
        SbkrqW::new(self, 1)
    }
    #[doc = "Bit 2 - Mute mode request"]
    #[inline(always)]
    #[must_use]
    pub fn mmrq(&mut self) -> MmrqW<RqrSpec> {
        MmrqW::new(self, 2)
    }
    #[doc = "Bit 3 - Receive data flush request"]
    #[inline(always)]
    #[must_use]
    pub fn rxfrq(&mut self) -> RxfrqW<RqrSpec> {
        RxfrqW::new(self, 3)
    }
    #[doc = "Bit 4 - Transmit data flush request"]
    #[inline(always)]
    #[must_use]
    pub fn txfrq(&mut self) -> TxfrqW<RqrSpec> {
        TxfrqW::new(self, 4)
    }
}
#[doc = "Request register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rqr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RqrSpec;
impl crate::RegisterSpec for RqrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`write(|w| ..)` method takes [`rqr::W`](W) writer structure"]
impl crate::Writable for RqrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RQR to value 0"]
impl crate::Resettable for RqrSpec {
    const RESET_VALUE: u32 = 0;
}
