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
#[doc = "Register `SR1` reader"]
pub type R = crate::R<Sr1Spec>;
#[doc = "Register `SR1` writer"]
pub type W = crate::W<Sr1Spec>;
#[doc = "Field `SB` reader - Start bit (Master mode)"]
pub type SbR = crate::BitReader;
#[doc = "Field `SB` writer - Start bit (Master mode)"]
pub type SbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADDR` reader - Address sent (master mode)/matched (slave mode)"]
pub type AddrR = crate::BitReader;
#[doc = "Field `ADDR` writer - Address sent (master mode)/matched (slave mode)"]
pub type AddrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BTF` reader - Byte transfer finished"]
pub type BtfR = crate::BitReader;
#[doc = "Field `BTF` writer - Byte transfer finished"]
pub type BtfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADD10` reader - 10-bit header sent (Master mode)"]
pub type Add10R = crate::BitReader;
#[doc = "Field `ADD10` writer - 10-bit header sent (Master mode)"]
pub type Add10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STOPF` reader - Stop detection (slave mode)"]
pub type StopfR = crate::BitReader;
#[doc = "Field `STOPF` writer - Stop detection (slave mode)"]
pub type StopfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RxNE` reader - Data register not empty (receivers)"]
pub type RxNeR = crate::BitReader;
#[doc = "Field `RxNE` writer - Data register not empty (receivers)"]
pub type RxNeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TxE` reader - Data register empty (transmitters)"]
pub type TxER = crate::BitReader;
#[doc = "Field `TxE` writer - Data register empty (transmitters)"]
pub type TxEW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BERR` reader - Bus error"]
pub type BerrR = crate::BitReader;
#[doc = "Field `BERR` writer - Bus error"]
pub type BerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARLO` reader - Arbitration lost (master mode)"]
pub type ArloR = crate::BitReader;
#[doc = "Field `ARLO` writer - Arbitration lost (master mode)"]
pub type ArloW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AF` reader - Acknowledge failure"]
pub type AfR = crate::BitReader;
#[doc = "Field `AF` writer - Acknowledge failure"]
pub type AfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR` reader - Overrun/Underrun"]
pub type OvrR = crate::BitReader;
#[doc = "Field `OVR` writer - Overrun/Underrun"]
pub type OvrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PECERR` reader - PEC Error in reception"]
pub type PecerrR = crate::BitReader;
#[doc = "Field `PECERR` writer - PEC Error in reception"]
pub type PecerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIMEOUT` reader - Timeout or Tlow error"]
pub type TimeoutR = crate::BitReader;
#[doc = "Field `TIMEOUT` writer - Timeout or Tlow error"]
pub type TimeoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMBALERT` reader - SMBus alert"]
pub type SmbalertR = crate::BitReader;
#[doc = "Field `SMBALERT` writer - SMBus alert"]
pub type SmbalertW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Start bit (Master mode)"]
    #[inline(always)]
    pub fn sb(&self) -> SbR {
        SbR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Address sent (master mode)/matched (slave mode)"]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Byte transfer finished"]
    #[inline(always)]
    pub fn btf(&self) -> BtfR {
        BtfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - 10-bit header sent (Master mode)"]
    #[inline(always)]
    pub fn add10(&self) -> Add10R {
        Add10R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Stop detection (slave mode)"]
    #[inline(always)]
    pub fn stopf(&self) -> StopfR {
        StopfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Data register not empty (receivers)"]
    #[inline(always)]
    pub fn rx_ne(&self) -> RxNeR {
        RxNeR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Data register empty (transmitters)"]
    #[inline(always)]
    pub fn tx_e(&self) -> TxER {
        TxER::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Bus error"]
    #[inline(always)]
    pub fn berr(&self) -> BerrR {
        BerrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Arbitration lost (master mode)"]
    #[inline(always)]
    pub fn arlo(&self) -> ArloR {
        ArloR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Acknowledge failure"]
    #[inline(always)]
    pub fn af(&self) -> AfR {
        AfR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Overrun/Underrun"]
    #[inline(always)]
    pub fn ovr(&self) -> OvrR {
        OvrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - PEC Error in reception"]
    #[inline(always)]
    pub fn pecerr(&self) -> PecerrR {
        PecerrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 14 - Timeout or Tlow error"]
    #[inline(always)]
    pub fn timeout(&self) -> TimeoutR {
        TimeoutR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - SMBus alert"]
    #[inline(always)]
    pub fn smbalert(&self) -> SmbalertR {
        SmbalertR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Start bit (Master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn sb(&mut self) -> SbW<Sr1Spec> {
        SbW::new(self, 0)
    }
    #[doc = "Bit 1 - Address sent (master mode)/matched (slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<Sr1Spec> {
        AddrW::new(self, 1)
    }
    #[doc = "Bit 2 - Byte transfer finished"]
    #[inline(always)]
    #[must_use]
    pub fn btf(&mut self) -> BtfW<Sr1Spec> {
        BtfW::new(self, 2)
    }
    #[doc = "Bit 3 - 10-bit header sent (Master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn add10(&mut self) -> Add10W<Sr1Spec> {
        Add10W::new(self, 3)
    }
    #[doc = "Bit 4 - Stop detection (slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn stopf(&mut self) -> StopfW<Sr1Spec> {
        StopfW::new(self, 4)
    }
    #[doc = "Bit 6 - Data register not empty (receivers)"]
    #[inline(always)]
    #[must_use]
    pub fn rx_ne(&mut self) -> RxNeW<Sr1Spec> {
        RxNeW::new(self, 6)
    }
    #[doc = "Bit 7 - Data register empty (transmitters)"]
    #[inline(always)]
    #[must_use]
    pub fn tx_e(&mut self) -> TxEW<Sr1Spec> {
        TxEW::new(self, 7)
    }
    #[doc = "Bit 8 - Bus error"]
    #[inline(always)]
    #[must_use]
    pub fn berr(&mut self) -> BerrW<Sr1Spec> {
        BerrW::new(self, 8)
    }
    #[doc = "Bit 9 - Arbitration lost (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn arlo(&mut self) -> ArloW<Sr1Spec> {
        ArloW::new(self, 9)
    }
    #[doc = "Bit 10 - Acknowledge failure"]
    #[inline(always)]
    #[must_use]
    pub fn af(&mut self) -> AfW<Sr1Spec> {
        AfW::new(self, 10)
    }
    #[doc = "Bit 11 - Overrun/Underrun"]
    #[inline(always)]
    #[must_use]
    pub fn ovr(&mut self) -> OvrW<Sr1Spec> {
        OvrW::new(self, 11)
    }
    #[doc = "Bit 12 - PEC Error in reception"]
    #[inline(always)]
    #[must_use]
    pub fn pecerr(&mut self) -> PecerrW<Sr1Spec> {
        PecerrW::new(self, 12)
    }
    #[doc = "Bit 14 - Timeout or Tlow error"]
    #[inline(always)]
    #[must_use]
    pub fn timeout(&mut self) -> TimeoutW<Sr1Spec> {
        TimeoutW::new(self, 14)
    }
    #[doc = "Bit 15 - SMBus alert"]
    #[inline(always)]
    #[must_use]
    pub fn smbalert(&mut self) -> SmbalertW<Sr1Spec> {
        SmbalertW::new(self, 15)
    }
}
#[doc = "Status register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sr1Spec;
impl crate::RegisterSpec for Sr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`sr1::R`](R) reader structure"]
impl crate::Readable for Sr1Spec {}
#[doc = "`write(|w| ..)` method takes [`sr1::W`](W) writer structure"]
impl crate::Writable for Sr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR1 to value 0"]
impl crate::Resettable for Sr1Spec {
    const RESET_VALUE: u32 = 0;
}
