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
#[doc = "Field `RXBR` reader - Rx-Byte Received"]
pub type RxbrR = crate::BitReader;
#[doc = "Field `RXBR` writer - Rx-Byte Received"]
pub type RxbrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXEND` reader - End Of Reception"]
pub type RxendR = crate::BitReader;
#[doc = "Field `RXEND` writer - End Of Reception"]
pub type RxendW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXOVR` reader - Rx-Overrun"]
pub type RxovrR = crate::BitReader;
#[doc = "Field `RXOVR` writer - Rx-Overrun"]
pub type RxovrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BRE` reader - Rx-Bit rising error"]
pub type BreR = crate::BitReader;
#[doc = "Field `BRE` writer - Rx-Bit rising error"]
pub type BreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBPE` reader - Rx-Short Bit period error"]
pub type SbpeR = crate::BitReader;
#[doc = "Field `SBPE` writer - Rx-Short Bit period error"]
pub type SbpeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LBPE` reader - Rx-Long Bit Period Error"]
pub type LbpeR = crate::BitReader;
#[doc = "Field `LBPE` writer - Rx-Long Bit Period Error"]
pub type LbpeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXACKE` reader - Rx-Missing Acknowledge"]
pub type RxackeR = crate::BitReader;
#[doc = "Field `RXACKE` writer - Rx-Missing Acknowledge"]
pub type RxackeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARBLST` reader - Arbitration Lost"]
pub type ArblstR = crate::BitReader;
#[doc = "Field `ARBLST` writer - Arbitration Lost"]
pub type ArblstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXBR` reader - Tx-Byte Request"]
pub type TxbrR = crate::BitReader;
#[doc = "Field `TXBR` writer - Tx-Byte Request"]
pub type TxbrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXEND` reader - End of Transmission"]
pub type TxendR = crate::BitReader;
#[doc = "Field `TXEND` writer - End of Transmission"]
pub type TxendW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXUDR` reader - Tx-Buffer Underrun"]
pub type TxudrR = crate::BitReader;
#[doc = "Field `TXUDR` writer - Tx-Buffer Underrun"]
pub type TxudrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXERR` reader - Tx-Error"]
pub type TxerrR = crate::BitReader;
#[doc = "Field `TXERR` writer - Tx-Error"]
pub type TxerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXACKE` reader - Tx-Missing acknowledge error"]
pub type TxackeR = crate::BitReader;
#[doc = "Field `TXACKE` writer - Tx-Missing acknowledge error"]
pub type TxackeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Rx-Byte Received"]
    #[inline(always)]
    pub fn rxbr(&self) -> RxbrR {
        RxbrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - End Of Reception"]
    #[inline(always)]
    pub fn rxend(&self) -> RxendR {
        RxendR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Rx-Overrun"]
    #[inline(always)]
    pub fn rxovr(&self) -> RxovrR {
        RxovrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Rx-Bit rising error"]
    #[inline(always)]
    pub fn bre(&self) -> BreR {
        BreR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Rx-Short Bit period error"]
    #[inline(always)]
    pub fn sbpe(&self) -> SbpeR {
        SbpeR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Rx-Long Bit Period Error"]
    #[inline(always)]
    pub fn lbpe(&self) -> LbpeR {
        LbpeR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Rx-Missing Acknowledge"]
    #[inline(always)]
    pub fn rxacke(&self) -> RxackeR {
        RxackeR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Arbitration Lost"]
    #[inline(always)]
    pub fn arblst(&self) -> ArblstR {
        ArblstR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Tx-Byte Request"]
    #[inline(always)]
    pub fn txbr(&self) -> TxbrR {
        TxbrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - End of Transmission"]
    #[inline(always)]
    pub fn txend(&self) -> TxendR {
        TxendR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Tx-Buffer Underrun"]
    #[inline(always)]
    pub fn txudr(&self) -> TxudrR {
        TxudrR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Tx-Error"]
    #[inline(always)]
    pub fn txerr(&self) -> TxerrR {
        TxerrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Tx-Missing acknowledge error"]
    #[inline(always)]
    pub fn txacke(&self) -> TxackeR {
        TxackeR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Rx-Byte Received"]
    #[inline(always)]
    #[must_use]
    pub fn rxbr(&mut self) -> RxbrW<IsrSpec> {
        RxbrW::new(self, 0)
    }
    #[doc = "Bit 1 - End Of Reception"]
    #[inline(always)]
    #[must_use]
    pub fn rxend(&mut self) -> RxendW<IsrSpec> {
        RxendW::new(self, 1)
    }
    #[doc = "Bit 2 - Rx-Overrun"]
    #[inline(always)]
    #[must_use]
    pub fn rxovr(&mut self) -> RxovrW<IsrSpec> {
        RxovrW::new(self, 2)
    }
    #[doc = "Bit 3 - Rx-Bit rising error"]
    #[inline(always)]
    #[must_use]
    pub fn bre(&mut self) -> BreW<IsrSpec> {
        BreW::new(self, 3)
    }
    #[doc = "Bit 4 - Rx-Short Bit period error"]
    #[inline(always)]
    #[must_use]
    pub fn sbpe(&mut self) -> SbpeW<IsrSpec> {
        SbpeW::new(self, 4)
    }
    #[doc = "Bit 5 - Rx-Long Bit Period Error"]
    #[inline(always)]
    #[must_use]
    pub fn lbpe(&mut self) -> LbpeW<IsrSpec> {
        LbpeW::new(self, 5)
    }
    #[doc = "Bit 6 - Rx-Missing Acknowledge"]
    #[inline(always)]
    #[must_use]
    pub fn rxacke(&mut self) -> RxackeW<IsrSpec> {
        RxackeW::new(self, 6)
    }
    #[doc = "Bit 7 - Arbitration Lost"]
    #[inline(always)]
    #[must_use]
    pub fn arblst(&mut self) -> ArblstW<IsrSpec> {
        ArblstW::new(self, 7)
    }
    #[doc = "Bit 8 - Tx-Byte Request"]
    #[inline(always)]
    #[must_use]
    pub fn txbr(&mut self) -> TxbrW<IsrSpec> {
        TxbrW::new(self, 8)
    }
    #[doc = "Bit 9 - End of Transmission"]
    #[inline(always)]
    #[must_use]
    pub fn txend(&mut self) -> TxendW<IsrSpec> {
        TxendW::new(self, 9)
    }
    #[doc = "Bit 10 - Tx-Buffer Underrun"]
    #[inline(always)]
    #[must_use]
    pub fn txudr(&mut self) -> TxudrW<IsrSpec> {
        TxudrW::new(self, 10)
    }
    #[doc = "Bit 11 - Tx-Error"]
    #[inline(always)]
    #[must_use]
    pub fn txerr(&mut self) -> TxerrW<IsrSpec> {
        TxerrW::new(self, 11)
    }
    #[doc = "Bit 12 - Tx-Missing acknowledge error"]
    #[inline(always)]
    #[must_use]
    pub fn txacke(&mut self) -> TxackeW<IsrSpec> {
        TxackeW::new(self, 12)
    }
}
#[doc = "Interrupt and Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`isr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`write(|w| ..)` method takes [`isr::W`](W) writer structure"]
impl crate::Writable for IsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ISR to value 0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0;
}
