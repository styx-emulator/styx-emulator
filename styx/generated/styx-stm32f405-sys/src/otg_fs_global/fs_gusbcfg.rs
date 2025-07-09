// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_GUSBCFG` reader"]
pub type R = crate::R<FsGusbcfgSpec>;
#[doc = "Register `FS_GUSBCFG` writer"]
pub type W = crate::W<FsGusbcfgSpec>;
#[doc = "Field `TOCAL` reader - FS timeout calibration"]
pub type TocalR = crate::FieldReader;
#[doc = "Field `TOCAL` writer - FS timeout calibration"]
pub type TocalW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `PHYSEL` reader - Full Speed serial transceiver select"]
pub type PhyselR = crate::BitReader;
#[doc = "Field `PHYSEL` writer - Full Speed serial transceiver select"]
pub type PhyselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRPCAP` reader - SRP-capable"]
pub type SrpcapR = crate::BitReader;
#[doc = "Field `SRPCAP` writer - SRP-capable"]
pub type SrpcapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNPCAP` reader - HNP-capable"]
pub type HnpcapR = crate::BitReader;
#[doc = "Field `HNPCAP` writer - HNP-capable"]
pub type HnpcapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TRDT` reader - USB turnaround time"]
pub type TrdtR = crate::FieldReader;
#[doc = "Field `TRDT` writer - USB turnaround time"]
pub type TrdtW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `FHMOD` reader - Force host mode"]
pub type FhmodR = crate::BitReader;
#[doc = "Field `FHMOD` writer - Force host mode"]
pub type FhmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FDMOD` reader - Force device mode"]
pub type FdmodR = crate::BitReader;
#[doc = "Field `FDMOD` writer - Force device mode"]
pub type FdmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTXPKT` reader - Corrupt Tx packet"]
pub type CtxpktR = crate::BitReader;
#[doc = "Field `CTXPKT` writer - Corrupt Tx packet"]
pub type CtxpktW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - FS timeout calibration"]
    #[inline(always)]
    pub fn tocal(&self) -> TocalR {
        TocalR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 6 - Full Speed serial transceiver select"]
    #[inline(always)]
    pub fn physel(&self) -> PhyselR {
        PhyselR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - SRP-capable"]
    #[inline(always)]
    pub fn srpcap(&self) -> SrpcapR {
        SrpcapR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - HNP-capable"]
    #[inline(always)]
    pub fn hnpcap(&self) -> HnpcapR {
        HnpcapR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:13 - USB turnaround time"]
    #[inline(always)]
    pub fn trdt(&self) -> TrdtR {
        TrdtR::new(((self.bits >> 10) & 0x0f) as u8)
    }
    #[doc = "Bit 29 - Force host mode"]
    #[inline(always)]
    pub fn fhmod(&self) -> FhmodR {
        FhmodR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Force device mode"]
    #[inline(always)]
    pub fn fdmod(&self) -> FdmodR {
        FdmodR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Corrupt Tx packet"]
    #[inline(always)]
    pub fn ctxpkt(&self) -> CtxpktR {
        CtxpktR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - FS timeout calibration"]
    #[inline(always)]
    #[must_use]
    pub fn tocal(&mut self) -> TocalW<FsGusbcfgSpec> {
        TocalW::new(self, 0)
    }
    #[doc = "Bit 6 - Full Speed serial transceiver select"]
    #[inline(always)]
    #[must_use]
    pub fn physel(&mut self) -> PhyselW<FsGusbcfgSpec> {
        PhyselW::new(self, 6)
    }
    #[doc = "Bit 8 - SRP-capable"]
    #[inline(always)]
    #[must_use]
    pub fn srpcap(&mut self) -> SrpcapW<FsGusbcfgSpec> {
        SrpcapW::new(self, 8)
    }
    #[doc = "Bit 9 - HNP-capable"]
    #[inline(always)]
    #[must_use]
    pub fn hnpcap(&mut self) -> HnpcapW<FsGusbcfgSpec> {
        HnpcapW::new(self, 9)
    }
    #[doc = "Bits 10:13 - USB turnaround time"]
    #[inline(always)]
    #[must_use]
    pub fn trdt(&mut self) -> TrdtW<FsGusbcfgSpec> {
        TrdtW::new(self, 10)
    }
    #[doc = "Bit 29 - Force host mode"]
    #[inline(always)]
    #[must_use]
    pub fn fhmod(&mut self) -> FhmodW<FsGusbcfgSpec> {
        FhmodW::new(self, 29)
    }
    #[doc = "Bit 30 - Force device mode"]
    #[inline(always)]
    #[must_use]
    pub fn fdmod(&mut self) -> FdmodW<FsGusbcfgSpec> {
        FdmodW::new(self, 30)
    }
    #[doc = "Bit 31 - Corrupt Tx packet"]
    #[inline(always)]
    #[must_use]
    pub fn ctxpkt(&mut self) -> CtxpktW<FsGusbcfgSpec> {
        CtxpktW::new(self, 31)
    }
}
#[doc = "OTG_FS USB configuration register (OTG_FS_GUSBCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_gusbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_gusbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsGusbcfgSpec;
impl crate::RegisterSpec for FsGusbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`fs_gusbcfg::R`](R) reader structure"]
impl crate::Readable for FsGusbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_gusbcfg::W`](W) writer structure"]
impl crate::Writable for FsGusbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_GUSBCFG to value 0x0a00"]
impl crate::Resettable for FsGusbcfgSpec {
    const RESET_VALUE: u32 = 0x0a00;
}
