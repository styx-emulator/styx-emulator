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
#[doc = "Register `ISR` reader"]
pub type R = crate::R<IsrSpec>;
#[doc = "Register `ISR` writer"]
pub type W = crate::W<IsrSpec>;
#[doc = "Field `TXE` reader - Transmit data register empty (transmitters)"]
pub type TxeR = crate::BitReader;
#[doc = "Field `TXE` writer - Transmit data register empty (transmitters)"]
pub type TxeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXIS` reader - Transmit interrupt status (transmitters)"]
pub type TxisR = crate::BitReader;
#[doc = "Field `TXIS` writer - Transmit interrupt status (transmitters)"]
pub type TxisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXNE` reader - Receive data register not empty (receivers)"]
pub type RxneR = crate::BitReader;
#[doc = "Field `RXNE` writer - Receive data register not empty (receivers)"]
pub type RxneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADDR` reader - Address matched (slave mode)"]
pub type AddrR = crate::BitReader;
#[doc = "Field `ADDR` writer - Address matched (slave mode)"]
pub type AddrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NACKF` reader - Not acknowledge received flag"]
pub type NackfR = crate::BitReader;
#[doc = "Field `NACKF` writer - Not acknowledge received flag"]
pub type NackfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STOPF` reader - Stop detection flag"]
pub type StopfR = crate::BitReader;
#[doc = "Field `STOPF` writer - Stop detection flag"]
pub type StopfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TC` reader - Transfer Complete (master mode)"]
pub type TcR = crate::BitReader;
#[doc = "Field `TC` writer - Transfer Complete (master mode)"]
pub type TcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCR` reader - Transfer Complete Reload"]
pub type TcrR = crate::BitReader;
#[doc = "Field `TCR` writer - Transfer Complete Reload"]
pub type TcrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BERR` reader - Bus error"]
pub type BerrR = crate::BitReader;
#[doc = "Field `BERR` writer - Bus error"]
pub type BerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARLO` reader - Arbitration lost"]
pub type ArloR = crate::BitReader;
#[doc = "Field `ARLO` writer - Arbitration lost"]
pub type ArloW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR` reader - Overrun/Underrun (slave mode)"]
pub type OvrR = crate::BitReader;
#[doc = "Field `OVR` writer - Overrun/Underrun (slave mode)"]
pub type OvrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PECERR` reader - PEC Error in reception"]
pub type PecerrR = crate::BitReader;
#[doc = "Field `PECERR` writer - PEC Error in reception"]
pub type PecerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIMEOUT` reader - Timeout or t_low detection flag"]
pub type TimeoutR = crate::BitReader;
#[doc = "Field `TIMEOUT` writer - Timeout or t_low detection flag"]
pub type TimeoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ALERT` reader - SMBus alert"]
pub type AlertR = crate::BitReader;
#[doc = "Field `ALERT` writer - SMBus alert"]
pub type AlertW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSY` reader - Bus busy"]
pub type BusyR = crate::BitReader;
#[doc = "Field `BUSY` writer - Bus busy"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DIR` reader - Transfer direction (Slave mode)"]
pub type DirR = crate::BitReader;
#[doc = "Field `DIR` writer - Transfer direction (Slave mode)"]
pub type DirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADDCODE` reader - Address match code (Slave mode)"]
pub type AddcodeR = crate::FieldReader;
#[doc = "Field `ADDCODE` writer - Address match code (Slave mode)"]
pub type AddcodeW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bit 0 - Transmit data register empty (transmitters)"]
    #[inline(always)]
    pub fn txe(&self) -> TxeR {
        TxeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Transmit interrupt status (transmitters)"]
    #[inline(always)]
    pub fn txis(&self) -> TxisR {
        TxisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Receive data register not empty (receivers)"]
    #[inline(always)]
    pub fn rxne(&self) -> RxneR {
        RxneR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Address matched (slave mode)"]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Not acknowledge received flag"]
    #[inline(always)]
    pub fn nackf(&self) -> NackfR {
        NackfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Stop detection flag"]
    #[inline(always)]
    pub fn stopf(&self) -> StopfR {
        StopfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Transfer Complete (master mode)"]
    #[inline(always)]
    pub fn tc(&self) -> TcR {
        TcR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Transfer Complete Reload"]
    #[inline(always)]
    pub fn tcr(&self) -> TcrR {
        TcrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Bus error"]
    #[inline(always)]
    pub fn berr(&self) -> BerrR {
        BerrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Arbitration lost"]
    #[inline(always)]
    pub fn arlo(&self) -> ArloR {
        ArloR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Overrun/Underrun (slave mode)"]
    #[inline(always)]
    pub fn ovr(&self) -> OvrR {
        OvrR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - PEC Error in reception"]
    #[inline(always)]
    pub fn pecerr(&self) -> PecerrR {
        PecerrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Timeout or t_low detection flag"]
    #[inline(always)]
    pub fn timeout(&self) -> TimeoutR {
        TimeoutR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - SMBus alert"]
    #[inline(always)]
    pub fn alert(&self) -> AlertR {
        AlertR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 15 - Bus busy"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Transfer direction (Slave mode)"]
    #[inline(always)]
    pub fn dir(&self) -> DirR {
        DirR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:23 - Address match code (Slave mode)"]
    #[inline(always)]
    pub fn addcode(&self) -> AddcodeR {
        AddcodeR::new(((self.bits >> 17) & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Transmit data register empty (transmitters)"]
    #[inline(always)]
    #[must_use]
    pub fn txe(&mut self) -> TxeW<IsrSpec> {
        TxeW::new(self, 0)
    }
    #[doc = "Bit 1 - Transmit interrupt status (transmitters)"]
    #[inline(always)]
    #[must_use]
    pub fn txis(&mut self) -> TxisW<IsrSpec> {
        TxisW::new(self, 1)
    }
    #[doc = "Bit 2 - Receive data register not empty (receivers)"]
    #[inline(always)]
    #[must_use]
    pub fn rxne(&mut self) -> RxneW<IsrSpec> {
        RxneW::new(self, 2)
    }
    #[doc = "Bit 3 - Address matched (slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<IsrSpec> {
        AddrW::new(self, 3)
    }
    #[doc = "Bit 4 - Not acknowledge received flag"]
    #[inline(always)]
    #[must_use]
    pub fn nackf(&mut self) -> NackfW<IsrSpec> {
        NackfW::new(self, 4)
    }
    #[doc = "Bit 5 - Stop detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn stopf(&mut self) -> StopfW<IsrSpec> {
        StopfW::new(self, 5)
    }
    #[doc = "Bit 6 - Transfer Complete (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn tc(&mut self) -> TcW<IsrSpec> {
        TcW::new(self, 6)
    }
    #[doc = "Bit 7 - Transfer Complete Reload"]
    #[inline(always)]
    #[must_use]
    pub fn tcr(&mut self) -> TcrW<IsrSpec> {
        TcrW::new(self, 7)
    }
    #[doc = "Bit 8 - Bus error"]
    #[inline(always)]
    #[must_use]
    pub fn berr(&mut self) -> BerrW<IsrSpec> {
        BerrW::new(self, 8)
    }
    #[doc = "Bit 9 - Arbitration lost"]
    #[inline(always)]
    #[must_use]
    pub fn arlo(&mut self) -> ArloW<IsrSpec> {
        ArloW::new(self, 9)
    }
    #[doc = "Bit 10 - Overrun/Underrun (slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn ovr(&mut self) -> OvrW<IsrSpec> {
        OvrW::new(self, 10)
    }
    #[doc = "Bit 11 - PEC Error in reception"]
    #[inline(always)]
    #[must_use]
    pub fn pecerr(&mut self) -> PecerrW<IsrSpec> {
        PecerrW::new(self, 11)
    }
    #[doc = "Bit 12 - Timeout or t_low detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn timeout(&mut self) -> TimeoutW<IsrSpec> {
        TimeoutW::new(self, 12)
    }
    #[doc = "Bit 13 - SMBus alert"]
    #[inline(always)]
    #[must_use]
    pub fn alert(&mut self) -> AlertW<IsrSpec> {
        AlertW::new(self, 13)
    }
    #[doc = "Bit 15 - Bus busy"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<IsrSpec> {
        BusyW::new(self, 15)
    }
    #[doc = "Bit 16 - Transfer direction (Slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn dir(&mut self) -> DirW<IsrSpec> {
        DirW::new(self, 16)
    }
    #[doc = "Bits 17:23 - Address match code (Slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn addcode(&mut self) -> AddcodeW<IsrSpec> {
        AddcodeW::new(self, 17)
    }
}
#[doc = "Interrupt and Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`isr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`write(|w| ..)` method takes [`isr::W`](W) writer structure"]
impl crate::Writable for IsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ISR to value 0x01"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0x01;
}
