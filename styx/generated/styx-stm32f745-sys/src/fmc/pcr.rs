// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PCR` reader"]
pub type R = crate::R<PcrSpec>;
#[doc = "Register `PCR` writer"]
pub type W = crate::W<PcrSpec>;
#[doc = "Field `PWAITEN` reader - PWAITEN"]
pub type PwaitenR = crate::BitReader;
#[doc = "Field `PWAITEN` writer - PWAITEN"]
pub type PwaitenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PBKEN` reader - PBKEN"]
pub type PbkenR = crate::BitReader;
#[doc = "Field `PBKEN` writer - PBKEN"]
pub type PbkenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTYP` reader - PTYP"]
pub type PtypR = crate::BitReader;
#[doc = "Field `PTYP` writer - PTYP"]
pub type PtypW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PWID` reader - PWID"]
pub type PwidR = crate::FieldReader;
#[doc = "Field `PWID` writer - PWID"]
pub type PwidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ECCEN` reader - ECCEN"]
pub type EccenR = crate::BitReader;
#[doc = "Field `ECCEN` writer - ECCEN"]
pub type EccenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCLR` reader - TCLR"]
pub type TclrR = crate::FieldReader;
#[doc = "Field `TCLR` writer - TCLR"]
pub type TclrW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TAR` reader - TAR"]
pub type TarR = crate::FieldReader;
#[doc = "Field `TAR` writer - TAR"]
pub type TarW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `ECCPS` reader - ECCPS"]
pub type EccpsR = crate::FieldReader;
#[doc = "Field `ECCPS` writer - ECCPS"]
pub type EccpsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bit 1 - PWAITEN"]
    #[inline(always)]
    pub fn pwaiten(&self) -> PwaitenR {
        PwaitenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - PBKEN"]
    #[inline(always)]
    pub fn pbken(&self) -> PbkenR {
        PbkenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - PTYP"]
    #[inline(always)]
    pub fn ptyp(&self) -> PtypR {
        PtypR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:5 - PWID"]
    #[inline(always)]
    pub fn pwid(&self) -> PwidR {
        PwidR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bit 6 - ECCEN"]
    #[inline(always)]
    pub fn eccen(&self) -> EccenR {
        EccenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 9:12 - TCLR"]
    #[inline(always)]
    pub fn tclr(&self) -> TclrR {
        TclrR::new(((self.bits >> 9) & 0x0f) as u8)
    }
    #[doc = "Bits 13:16 - TAR"]
    #[inline(always)]
    pub fn tar(&self) -> TarR {
        TarR::new(((self.bits >> 13) & 0x0f) as u8)
    }
    #[doc = "Bits 17:19 - ECCPS"]
    #[inline(always)]
    pub fn eccps(&self) -> EccpsR {
        EccpsR::new(((self.bits >> 17) & 7) as u8)
    }
}
impl W {
    #[doc = "Bit 1 - PWAITEN"]
    #[inline(always)]
    #[must_use]
    pub fn pwaiten(&mut self) -> PwaitenW<PcrSpec> {
        PwaitenW::new(self, 1)
    }
    #[doc = "Bit 2 - PBKEN"]
    #[inline(always)]
    #[must_use]
    pub fn pbken(&mut self) -> PbkenW<PcrSpec> {
        PbkenW::new(self, 2)
    }
    #[doc = "Bit 3 - PTYP"]
    #[inline(always)]
    #[must_use]
    pub fn ptyp(&mut self) -> PtypW<PcrSpec> {
        PtypW::new(self, 3)
    }
    #[doc = "Bits 4:5 - PWID"]
    #[inline(always)]
    #[must_use]
    pub fn pwid(&mut self) -> PwidW<PcrSpec> {
        PwidW::new(self, 4)
    }
    #[doc = "Bit 6 - ECCEN"]
    #[inline(always)]
    #[must_use]
    pub fn eccen(&mut self) -> EccenW<PcrSpec> {
        EccenW::new(self, 6)
    }
    #[doc = "Bits 9:12 - TCLR"]
    #[inline(always)]
    #[must_use]
    pub fn tclr(&mut self) -> TclrW<PcrSpec> {
        TclrW::new(self, 9)
    }
    #[doc = "Bits 13:16 - TAR"]
    #[inline(always)]
    #[must_use]
    pub fn tar(&mut self) -> TarW<PcrSpec> {
        TarW::new(self, 13)
    }
    #[doc = "Bits 17:19 - ECCPS"]
    #[inline(always)]
    #[must_use]
    pub fn eccps(&mut self) -> EccpsW<PcrSpec> {
        EccpsW::new(self, 17)
    }
}
#[doc = "PC Card/NAND Flash control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PcrSpec;
impl crate::RegisterSpec for PcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`pcr::R`](R) reader structure"]
impl crate::Readable for PcrSpec {}
#[doc = "`write(|w| ..)` method takes [`pcr::W`](W) writer structure"]
impl crate::Writable for PcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PCR to value 0x18"]
impl crate::Resettable for PcrSpec {
    const RESET_VALUE: u32 = 0x18;
}
