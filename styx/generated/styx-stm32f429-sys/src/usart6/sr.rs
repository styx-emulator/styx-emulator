// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `PE` reader - Parity error"]
pub type PeR = crate::BitReader;
#[doc = "Field `PE` writer - Parity error"]
pub type PeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FE` reader - Framing error"]
pub type FeR = crate::BitReader;
#[doc = "Field `FE` writer - Framing error"]
pub type FeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NF` reader - Noise detected flag"]
pub type NfR = crate::BitReader;
#[doc = "Field `NF` writer - Noise detected flag"]
pub type NfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ORE` reader - Overrun error"]
pub type OreR = crate::BitReader;
#[doc = "Field `ORE` writer - Overrun error"]
pub type OreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDLE` reader - IDLE line detected"]
pub type IdleR = crate::BitReader;
#[doc = "Field `IDLE` writer - IDLE line detected"]
pub type IdleW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXNE` reader - Read data register not empty"]
pub type RxneR = crate::BitReader;
#[doc = "Field `RXNE` writer - Read data register not empty"]
pub type RxneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TC` reader - Transmission complete"]
pub type TcR = crate::BitReader;
#[doc = "Field `TC` writer - Transmission complete"]
pub type TcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXE` reader - Transmit data register empty"]
pub type TxeR = crate::BitReader;
#[doc = "Field `TXE` writer - Transmit data register empty"]
pub type TxeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LBD` reader - LIN break detection flag"]
pub type LbdR = crate::BitReader;
#[doc = "Field `LBD` writer - LIN break detection flag"]
pub type LbdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTS` reader - CTS flag"]
pub type CtsR = crate::BitReader;
#[doc = "Field `CTS` writer - CTS flag"]
pub type CtsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Parity error"]
    #[inline(always)]
    pub fn pe(&self) -> PeR {
        PeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Framing error"]
    #[inline(always)]
    pub fn fe(&self) -> FeR {
        FeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Noise detected flag"]
    #[inline(always)]
    pub fn nf(&self) -> NfR {
        NfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Overrun error"]
    #[inline(always)]
    pub fn ore(&self) -> OreR {
        OreR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - IDLE line detected"]
    #[inline(always)]
    pub fn idle(&self) -> IdleR {
        IdleR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Read data register not empty"]
    #[inline(always)]
    pub fn rxne(&self) -> RxneR {
        RxneR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Transmission complete"]
    #[inline(always)]
    pub fn tc(&self) -> TcR {
        TcR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Transmit data register empty"]
    #[inline(always)]
    pub fn txe(&self) -> TxeR {
        TxeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - LIN break detection flag"]
    #[inline(always)]
    pub fn lbd(&self) -> LbdR {
        LbdR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - CTS flag"]
    #[inline(always)]
    pub fn cts(&self) -> CtsR {
        CtsR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Parity error"]
    #[inline(always)]
    #[must_use]
    pub fn pe(&mut self) -> PeW<SrSpec> {
        PeW::new(self, 0)
    }
    #[doc = "Bit 1 - Framing error"]
    #[inline(always)]
    #[must_use]
    pub fn fe(&mut self) -> FeW<SrSpec> {
        FeW::new(self, 1)
    }
    #[doc = "Bit 2 - Noise detected flag"]
    #[inline(always)]
    #[must_use]
    pub fn nf(&mut self) -> NfW<SrSpec> {
        NfW::new(self, 2)
    }
    #[doc = "Bit 3 - Overrun error"]
    #[inline(always)]
    #[must_use]
    pub fn ore(&mut self) -> OreW<SrSpec> {
        OreW::new(self, 3)
    }
    #[doc = "Bit 4 - IDLE line detected"]
    #[inline(always)]
    #[must_use]
    pub fn idle(&mut self) -> IdleW<SrSpec> {
        IdleW::new(self, 4)
    }
    #[doc = "Bit 5 - Read data register not empty"]
    #[inline(always)]
    #[must_use]
    pub fn rxne(&mut self) -> RxneW<SrSpec> {
        RxneW::new(self, 5)
    }
    #[doc = "Bit 6 - Transmission complete"]
    #[inline(always)]
    #[must_use]
    pub fn tc(&mut self) -> TcW<SrSpec> {
        TcW::new(self, 6)
    }
    #[doc = "Bit 7 - Transmit data register empty"]
    #[inline(always)]
    #[must_use]
    pub fn txe(&mut self) -> TxeW<SrSpec> {
        TxeW::new(self, 7)
    }
    #[doc = "Bit 8 - LIN break detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn lbd(&mut self) -> LbdW<SrSpec> {
        LbdW::new(self, 8)
    }
    #[doc = "Bit 9 - CTS flag"]
    #[inline(always)]
    #[must_use]
    pub fn cts(&mut self) -> CtsW<SrSpec> {
        CtsW::new(self, 9)
    }
}
#[doc = "Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`write(|w| ..)` method takes [`sr::W`](W) writer structure"]
impl crate::Writable for SrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR to value 0x00c0_0000"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0x00c0_0000;
}
