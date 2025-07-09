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
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `RXNE` reader - Receive buffer not empty"]
pub type RxneR = crate::BitReader;
#[doc = "Field `RXNE` writer - Receive buffer not empty"]
pub type RxneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXE` reader - Transmit buffer empty"]
pub type TxeR = crate::BitReader;
#[doc = "Field `TXE` writer - Transmit buffer empty"]
pub type TxeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHSIDE` reader - Channel side"]
pub type ChsideR = crate::BitReader;
#[doc = "Field `CHSIDE` writer - Channel side"]
pub type ChsideW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UDR` reader - Underrun flag"]
pub type UdrR = crate::BitReader;
#[doc = "Field `UDR` writer - Underrun flag"]
pub type UdrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CRCERR` reader - CRC error flag"]
pub type CrcerrR = crate::BitReader;
#[doc = "Field `CRCERR` writer - CRC error flag"]
pub type CrcerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MODF` reader - Mode fault"]
pub type ModfR = crate::BitReader;
#[doc = "Field `MODF` writer - Mode fault"]
pub type ModfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR` reader - Overrun flag"]
pub type OvrR = crate::BitReader;
#[doc = "Field `OVR` writer - Overrun flag"]
pub type OvrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BSY` reader - Busy flag"]
pub type BsyR = crate::BitReader;
#[doc = "Field `BSY` writer - Busy flag"]
pub type BsyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIFRFE` reader - TI frame format error"]
pub type TifrfeR = crate::BitReader;
#[doc = "Field `TIFRFE` writer - TI frame format error"]
pub type TifrfeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Receive buffer not empty"]
    #[inline(always)]
    pub fn rxne(&self) -> RxneR {
        RxneR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Transmit buffer empty"]
    #[inline(always)]
    pub fn txe(&self) -> TxeR {
        TxeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Channel side"]
    #[inline(always)]
    pub fn chside(&self) -> ChsideR {
        ChsideR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Underrun flag"]
    #[inline(always)]
    pub fn udr(&self) -> UdrR {
        UdrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - CRC error flag"]
    #[inline(always)]
    pub fn crcerr(&self) -> CrcerrR {
        CrcerrR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Mode fault"]
    #[inline(always)]
    pub fn modf(&self) -> ModfR {
        ModfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Overrun flag"]
    #[inline(always)]
    pub fn ovr(&self) -> OvrR {
        OvrR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Busy flag"]
    #[inline(always)]
    pub fn bsy(&self) -> BsyR {
        BsyR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - TI frame format error"]
    #[inline(always)]
    pub fn tifrfe(&self) -> TifrfeR {
        TifrfeR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Receive buffer not empty"]
    #[inline(always)]
    #[must_use]
    pub fn rxne(&mut self) -> RxneW<SrSpec> {
        RxneW::new(self, 0)
    }
    #[doc = "Bit 1 - Transmit buffer empty"]
    #[inline(always)]
    #[must_use]
    pub fn txe(&mut self) -> TxeW<SrSpec> {
        TxeW::new(self, 1)
    }
    #[doc = "Bit 2 - Channel side"]
    #[inline(always)]
    #[must_use]
    pub fn chside(&mut self) -> ChsideW<SrSpec> {
        ChsideW::new(self, 2)
    }
    #[doc = "Bit 3 - Underrun flag"]
    #[inline(always)]
    #[must_use]
    pub fn udr(&mut self) -> UdrW<SrSpec> {
        UdrW::new(self, 3)
    }
    #[doc = "Bit 4 - CRC error flag"]
    #[inline(always)]
    #[must_use]
    pub fn crcerr(&mut self) -> CrcerrW<SrSpec> {
        CrcerrW::new(self, 4)
    }
    #[doc = "Bit 5 - Mode fault"]
    #[inline(always)]
    #[must_use]
    pub fn modf(&mut self) -> ModfW<SrSpec> {
        ModfW::new(self, 5)
    }
    #[doc = "Bit 6 - Overrun flag"]
    #[inline(always)]
    #[must_use]
    pub fn ovr(&mut self) -> OvrW<SrSpec> {
        OvrW::new(self, 6)
    }
    #[doc = "Bit 7 - Busy flag"]
    #[inline(always)]
    #[must_use]
    pub fn bsy(&mut self) -> BsyW<SrSpec> {
        BsyW::new(self, 7)
    }
    #[doc = "Bit 8 - TI frame format error"]
    #[inline(always)]
    #[must_use]
    pub fn tifrfe(&mut self) -> TifrfeW<SrSpec> {
        TifrfeW::new(self, 8)
    }
}
#[doc = "status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`write(|w| ..)` method takes [`sr::W`](W) writer structure"]
impl crate::Writable for SrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR to value 0x02"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0x02;
}
