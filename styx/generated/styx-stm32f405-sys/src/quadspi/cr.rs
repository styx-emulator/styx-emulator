// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `EN` reader - Enable"]
pub type EnR = crate::BitReader;
#[doc = "Field `EN` writer - Enable"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ABORT` reader - Abort request"]
pub type AbortR = crate::BitReader;
#[doc = "Field `ABORT` writer - Abort request"]
pub type AbortW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMAEN` reader - DMA enable"]
pub type DmaenR = crate::BitReader;
#[doc = "Field `DMAEN` writer - DMA enable"]
pub type DmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCEN` reader - Timeout counter enable"]
pub type TcenR = crate::BitReader;
#[doc = "Field `TCEN` writer - Timeout counter enable"]
pub type TcenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SSHIFT` reader - Sample shift"]
pub type SshiftR = crate::BitReader;
#[doc = "Field `SSHIFT` writer - Sample shift"]
pub type SshiftW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DFM` reader - Dual-flash mode"]
pub type DfmR = crate::BitReader;
#[doc = "Field `DFM` writer - Dual-flash mode"]
pub type DfmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FSEL` reader - FLASH memory selection"]
pub type FselR = crate::BitReader;
#[doc = "Field `FSEL` writer - FLASH memory selection"]
pub type FselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FTHRES` reader - IFO threshold level"]
pub type FthresR = crate::FieldReader;
#[doc = "Field `FTHRES` writer - IFO threshold level"]
pub type FthresW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `TEIE` reader - Transfer error interrupt enable"]
pub type TeieR = crate::BitReader;
#[doc = "Field `TEIE` writer - Transfer error interrupt enable"]
pub type TeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIE` reader - Transfer complete interrupt enable"]
pub type TcieR = crate::BitReader;
#[doc = "Field `TCIE` writer - Transfer complete interrupt enable"]
pub type TcieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FTIE` reader - FIFO threshold interrupt enable"]
pub type FtieR = crate::BitReader;
#[doc = "Field `FTIE` writer - FIFO threshold interrupt enable"]
pub type FtieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SMIE` reader - Status match interrupt enable"]
pub type SmieR = crate::BitReader;
#[doc = "Field `SMIE` writer - Status match interrupt enable"]
pub type SmieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TOIE` reader - TimeOut interrupt enable"]
pub type ToieR = crate::BitReader;
#[doc = "Field `TOIE` writer - TimeOut interrupt enable"]
pub type ToieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `APMS` reader - Automatic poll mode stop"]
pub type ApmsR = crate::BitReader;
#[doc = "Field `APMS` writer - Automatic poll mode stop"]
pub type ApmsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PMM` reader - Polling match mode"]
pub type PmmR = crate::BitReader;
#[doc = "Field `PMM` writer - Polling match mode"]
pub type PmmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRESCALER` reader - Clock prescaler"]
pub type PrescalerR = crate::FieldReader;
#[doc = "Field `PRESCALER` writer - Clock prescaler"]
pub type PrescalerW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bit 0 - Enable"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Abort request"]
    #[inline(always)]
    pub fn abort(&self) -> AbortR {
        AbortR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - DMA enable"]
    #[inline(always)]
    pub fn dmaen(&self) -> DmaenR {
        DmaenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Timeout counter enable"]
    #[inline(always)]
    pub fn tcen(&self) -> TcenR {
        TcenR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Sample shift"]
    #[inline(always)]
    pub fn sshift(&self) -> SshiftR {
        SshiftR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Dual-flash mode"]
    #[inline(always)]
    pub fn dfm(&self) -> DfmR {
        DfmR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - FLASH memory selection"]
    #[inline(always)]
    pub fn fsel(&self) -> FselR {
        FselR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:12 - IFO threshold level"]
    #[inline(always)]
    pub fn fthres(&self) -> FthresR {
        FthresR::new(((self.bits >> 8) & 0x1f) as u8)
    }
    #[doc = "Bit 16 - Transfer error interrupt enable"]
    #[inline(always)]
    pub fn teie(&self) -> TeieR {
        TeieR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Transfer complete interrupt enable"]
    #[inline(always)]
    pub fn tcie(&self) -> TcieR {
        TcieR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - FIFO threshold interrupt enable"]
    #[inline(always)]
    pub fn ftie(&self) -> FtieR {
        FtieR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Status match interrupt enable"]
    #[inline(always)]
    pub fn smie(&self) -> SmieR {
        SmieR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - TimeOut interrupt enable"]
    #[inline(always)]
    pub fn toie(&self) -> ToieR {
        ToieR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 22 - Automatic poll mode stop"]
    #[inline(always)]
    pub fn apms(&self) -> ApmsR {
        ApmsR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Polling match mode"]
    #[inline(always)]
    pub fn pmm(&self) -> PmmR {
        PmmR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:31 - Clock prescaler"]
    #[inline(always)]
    pub fn prescaler(&self) -> PrescalerR {
        PrescalerR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Enable"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<CrSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Abort request"]
    #[inline(always)]
    #[must_use]
    pub fn abort(&mut self) -> AbortW<CrSpec> {
        AbortW::new(self, 1)
    }
    #[doc = "Bit 2 - DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen(&mut self) -> DmaenW<CrSpec> {
        DmaenW::new(self, 2)
    }
    #[doc = "Bit 3 - Timeout counter enable"]
    #[inline(always)]
    #[must_use]
    pub fn tcen(&mut self) -> TcenW<CrSpec> {
        TcenW::new(self, 3)
    }
    #[doc = "Bit 4 - Sample shift"]
    #[inline(always)]
    #[must_use]
    pub fn sshift(&mut self) -> SshiftW<CrSpec> {
        SshiftW::new(self, 4)
    }
    #[doc = "Bit 6 - Dual-flash mode"]
    #[inline(always)]
    #[must_use]
    pub fn dfm(&mut self) -> DfmW<CrSpec> {
        DfmW::new(self, 6)
    }
    #[doc = "Bit 7 - FLASH memory selection"]
    #[inline(always)]
    #[must_use]
    pub fn fsel(&mut self) -> FselW<CrSpec> {
        FselW::new(self, 7)
    }
    #[doc = "Bits 8:12 - IFO threshold level"]
    #[inline(always)]
    #[must_use]
    pub fn fthres(&mut self) -> FthresW<CrSpec> {
        FthresW::new(self, 8)
    }
    #[doc = "Bit 16 - Transfer error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn teie(&mut self) -> TeieW<CrSpec> {
        TeieW::new(self, 16)
    }
    #[doc = "Bit 17 - Transfer complete interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tcie(&mut self) -> TcieW<CrSpec> {
        TcieW::new(self, 17)
    }
    #[doc = "Bit 18 - FIFO threshold interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ftie(&mut self) -> FtieW<CrSpec> {
        FtieW::new(self, 18)
    }
    #[doc = "Bit 19 - Status match interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn smie(&mut self) -> SmieW<CrSpec> {
        SmieW::new(self, 19)
    }
    #[doc = "Bit 20 - TimeOut interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn toie(&mut self) -> ToieW<CrSpec> {
        ToieW::new(self, 20)
    }
    #[doc = "Bit 22 - Automatic poll mode stop"]
    #[inline(always)]
    #[must_use]
    pub fn apms(&mut self) -> ApmsW<CrSpec> {
        ApmsW::new(self, 22)
    }
    #[doc = "Bit 23 - Polling match mode"]
    #[inline(always)]
    #[must_use]
    pub fn pmm(&mut self) -> PmmW<CrSpec> {
        PmmW::new(self, 23)
    }
    #[doc = "Bits 24:31 - Clock prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn prescaler(&mut self) -> PrescalerW<CrSpec> {
        PrescalerW::new(self, 24)
    }
}
#[doc = "control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0;
}
