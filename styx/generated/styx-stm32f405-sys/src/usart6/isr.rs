// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ISR` reader"]
pub type R = crate::R<IsrSpec>;
#[doc = "Register `ISR` writer"]
pub type W = crate::W<IsrSpec>;
#[doc = "Field `PE` reader - PE"]
pub type PeR = crate::BitReader;
#[doc = "Field `PE` writer - PE"]
pub type PeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FE` reader - FE"]
pub type FeR = crate::BitReader;
#[doc = "Field `FE` writer - FE"]
pub type FeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NF` reader - NF"]
pub type NfR = crate::BitReader;
#[doc = "Field `NF` writer - NF"]
pub type NfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ORE` reader - ORE"]
pub type OreR = crate::BitReader;
#[doc = "Field `ORE` writer - ORE"]
pub type OreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDLE` reader - IDLE"]
pub type IdleR = crate::BitReader;
#[doc = "Field `IDLE` writer - IDLE"]
pub type IdleW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXNE` reader - RXNE"]
pub type RxneR = crate::BitReader;
#[doc = "Field `RXNE` writer - RXNE"]
pub type RxneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TC` reader - TC"]
pub type TcR = crate::BitReader;
#[doc = "Field `TC` writer - TC"]
pub type TcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXE` reader - TXE"]
pub type TxeR = crate::BitReader;
#[doc = "Field `TXE` writer - TXE"]
pub type TxeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LBDF` reader - LBDF"]
pub type LbdfR = crate::BitReader;
#[doc = "Field `LBDF` writer - LBDF"]
pub type LbdfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTSIF` reader - CTSIF"]
pub type CtsifR = crate::BitReader;
#[doc = "Field `CTSIF` writer - CTSIF"]
pub type CtsifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTS` reader - CTS"]
pub type CtsR = crate::BitReader;
#[doc = "Field `CTS` writer - CTS"]
pub type CtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RTOF` reader - RTOF"]
pub type RtofR = crate::BitReader;
#[doc = "Field `RTOF` writer - RTOF"]
pub type RtofW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOBF` reader - EOBF"]
pub type EobfR = crate::BitReader;
#[doc = "Field `EOBF` writer - EOBF"]
pub type EobfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ABRE` reader - ABRE"]
pub type AbreR = crate::BitReader;
#[doc = "Field `ABRE` writer - ABRE"]
pub type AbreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ABRF` reader - ABRF"]
pub type AbrfR = crate::BitReader;
#[doc = "Field `ABRF` writer - ABRF"]
pub type AbrfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSY` reader - BUSY"]
pub type BusyR = crate::BitReader;
#[doc = "Field `BUSY` writer - BUSY"]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMF` reader - CMF"]
pub type CmfR = crate::BitReader;
#[doc = "Field `CMF` writer - CMF"]
pub type CmfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SBKF` reader - SBKF"]
pub type SbkfR = crate::BitReader;
#[doc = "Field `SBKF` writer - SBKF"]
pub type SbkfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RWU` reader - RWU"]
pub type RwuR = crate::BitReader;
#[doc = "Field `RWU` writer - RWU"]
pub type RwuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUF` reader - WUF"]
pub type WufR = crate::BitReader;
#[doc = "Field `WUF` writer - WUF"]
pub type WufW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEACK` reader - TEACK"]
pub type TeackR = crate::BitReader;
#[doc = "Field `TEACK` writer - TEACK"]
pub type TeackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `REACK` reader - REACK"]
pub type ReackR = crate::BitReader;
#[doc = "Field `REACK` writer - REACK"]
pub type ReackW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - PE"]
    #[inline(always)]
    pub fn pe(&self) -> PeR {
        PeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - FE"]
    #[inline(always)]
    pub fn fe(&self) -> FeR {
        FeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - NF"]
    #[inline(always)]
    pub fn nf(&self) -> NfR {
        NfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - ORE"]
    #[inline(always)]
    pub fn ore(&self) -> OreR {
        OreR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - IDLE"]
    #[inline(always)]
    pub fn idle(&self) -> IdleR {
        IdleR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - RXNE"]
    #[inline(always)]
    pub fn rxne(&self) -> RxneR {
        RxneR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - TC"]
    #[inline(always)]
    pub fn tc(&self) -> TcR {
        TcR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - TXE"]
    #[inline(always)]
    pub fn txe(&self) -> TxeR {
        TxeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - LBDF"]
    #[inline(always)]
    pub fn lbdf(&self) -> LbdfR {
        LbdfR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - CTSIF"]
    #[inline(always)]
    pub fn ctsif(&self) -> CtsifR {
        CtsifR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - CTS"]
    #[inline(always)]
    pub fn cts(&self) -> CtsR {
        CtsR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - RTOF"]
    #[inline(always)]
    pub fn rtof(&self) -> RtofR {
        RtofR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - EOBF"]
    #[inline(always)]
    pub fn eobf(&self) -> EobfR {
        EobfR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 14 - ABRE"]
    #[inline(always)]
    pub fn abre(&self) -> AbreR {
        AbreR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - ABRF"]
    #[inline(always)]
    pub fn abrf(&self) -> AbrfR {
        AbrfR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - BUSY"]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - CMF"]
    #[inline(always)]
    pub fn cmf(&self) -> CmfR {
        CmfR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - SBKF"]
    #[inline(always)]
    pub fn sbkf(&self) -> SbkfR {
        SbkfR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - RWU"]
    #[inline(always)]
    pub fn rwu(&self) -> RwuR {
        RwuR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - WUF"]
    #[inline(always)]
    pub fn wuf(&self) -> WufR {
        WufR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - TEACK"]
    #[inline(always)]
    pub fn teack(&self) -> TeackR {
        TeackR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - REACK"]
    #[inline(always)]
    pub fn reack(&self) -> ReackR {
        ReackR::new(((self.bits >> 22) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - PE"]
    #[inline(always)]
    #[must_use]
    pub fn pe(&mut self) -> PeW<IsrSpec> {
        PeW::new(self, 0)
    }
    #[doc = "Bit 1 - FE"]
    #[inline(always)]
    #[must_use]
    pub fn fe(&mut self) -> FeW<IsrSpec> {
        FeW::new(self, 1)
    }
    #[doc = "Bit 2 - NF"]
    #[inline(always)]
    #[must_use]
    pub fn nf(&mut self) -> NfW<IsrSpec> {
        NfW::new(self, 2)
    }
    #[doc = "Bit 3 - ORE"]
    #[inline(always)]
    #[must_use]
    pub fn ore(&mut self) -> OreW<IsrSpec> {
        OreW::new(self, 3)
    }
    #[doc = "Bit 4 - IDLE"]
    #[inline(always)]
    #[must_use]
    pub fn idle(&mut self) -> IdleW<IsrSpec> {
        IdleW::new(self, 4)
    }
    #[doc = "Bit 5 - RXNE"]
    #[inline(always)]
    #[must_use]
    pub fn rxne(&mut self) -> RxneW<IsrSpec> {
        RxneW::new(self, 5)
    }
    #[doc = "Bit 6 - TC"]
    #[inline(always)]
    #[must_use]
    pub fn tc(&mut self) -> TcW<IsrSpec> {
        TcW::new(self, 6)
    }
    #[doc = "Bit 7 - TXE"]
    #[inline(always)]
    #[must_use]
    pub fn txe(&mut self) -> TxeW<IsrSpec> {
        TxeW::new(self, 7)
    }
    #[doc = "Bit 8 - LBDF"]
    #[inline(always)]
    #[must_use]
    pub fn lbdf(&mut self) -> LbdfW<IsrSpec> {
        LbdfW::new(self, 8)
    }
    #[doc = "Bit 9 - CTSIF"]
    #[inline(always)]
    #[must_use]
    pub fn ctsif(&mut self) -> CtsifW<IsrSpec> {
        CtsifW::new(self, 9)
    }
    #[doc = "Bit 10 - CTS"]
    #[inline(always)]
    #[must_use]
    pub fn cts(&mut self) -> CtsW<IsrSpec> {
        CtsW::new(self, 10)
    }
    #[doc = "Bit 11 - RTOF"]
    #[inline(always)]
    #[must_use]
    pub fn rtof(&mut self) -> RtofW<IsrSpec> {
        RtofW::new(self, 11)
    }
    #[doc = "Bit 12 - EOBF"]
    #[inline(always)]
    #[must_use]
    pub fn eobf(&mut self) -> EobfW<IsrSpec> {
        EobfW::new(self, 12)
    }
    #[doc = "Bit 14 - ABRE"]
    #[inline(always)]
    #[must_use]
    pub fn abre(&mut self) -> AbreW<IsrSpec> {
        AbreW::new(self, 14)
    }
    #[doc = "Bit 15 - ABRF"]
    #[inline(always)]
    #[must_use]
    pub fn abrf(&mut self) -> AbrfW<IsrSpec> {
        AbrfW::new(self, 15)
    }
    #[doc = "Bit 16 - BUSY"]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<IsrSpec> {
        BusyW::new(self, 16)
    }
    #[doc = "Bit 17 - CMF"]
    #[inline(always)]
    #[must_use]
    pub fn cmf(&mut self) -> CmfW<IsrSpec> {
        CmfW::new(self, 17)
    }
    #[doc = "Bit 18 - SBKF"]
    #[inline(always)]
    #[must_use]
    pub fn sbkf(&mut self) -> SbkfW<IsrSpec> {
        SbkfW::new(self, 18)
    }
    #[doc = "Bit 19 - RWU"]
    #[inline(always)]
    #[must_use]
    pub fn rwu(&mut self) -> RwuW<IsrSpec> {
        RwuW::new(self, 19)
    }
    #[doc = "Bit 20 - WUF"]
    #[inline(always)]
    #[must_use]
    pub fn wuf(&mut self) -> WufW<IsrSpec> {
        WufW::new(self, 20)
    }
    #[doc = "Bit 21 - TEACK"]
    #[inline(always)]
    #[must_use]
    pub fn teack(&mut self) -> TeackW<IsrSpec> {
        TeackW::new(self, 21)
    }
    #[doc = "Bit 22 - REACK"]
    #[inline(always)]
    #[must_use]
    pub fn reack(&mut self) -> ReackW<IsrSpec> {
        ReackW::new(self, 22)
    }
}
#[doc = "Interrupt &amp; status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`reset()` method sets ISR to value 0xc0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0xc0;
}
