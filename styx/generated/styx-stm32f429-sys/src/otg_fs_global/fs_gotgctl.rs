// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_GOTGCTL` reader"]
pub type R = crate::R<FsGotgctlSpec>;
#[doc = "Register `FS_GOTGCTL` writer"]
pub type W = crate::W<FsGotgctlSpec>;
#[doc = "Field `SRQSCS` reader - Session request success"]
pub type SrqscsR = crate::BitReader;
#[doc = "Field `SRQSCS` writer - Session request success"]
pub type SrqscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRQ` reader - Session request"]
pub type SrqR = crate::BitReader;
#[doc = "Field `SRQ` writer - Session request"]
pub type SrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNGSCS` reader - Host negotiation success"]
pub type HngscsR = crate::BitReader;
#[doc = "Field `HNGSCS` writer - Host negotiation success"]
pub type HngscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNPRQ` reader - HNP request"]
pub type HnprqR = crate::BitReader;
#[doc = "Field `HNPRQ` writer - HNP request"]
pub type HnprqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSHNPEN` reader - Host set HNP enable"]
pub type HshnpenR = crate::BitReader;
#[doc = "Field `HSHNPEN` writer - Host set HNP enable"]
pub type HshnpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DHNPEN` reader - Device HNP enabled"]
pub type DhnpenR = crate::BitReader;
#[doc = "Field `DHNPEN` writer - Device HNP enabled"]
pub type DhnpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CIDSTS` reader - Connector ID status"]
pub type CidstsR = crate::BitReader;
#[doc = "Field `CIDSTS` writer - Connector ID status"]
pub type CidstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBCT` reader - Long/short debounce time"]
pub type DbctR = crate::BitReader;
#[doc = "Field `DBCT` writer - Long/short debounce time"]
pub type DbctW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ASVLD` reader - A-session valid"]
pub type AsvldR = crate::BitReader;
#[doc = "Field `ASVLD` writer - A-session valid"]
pub type AsvldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BSVLD` reader - B-session valid"]
pub type BsvldR = crate::BitReader;
#[doc = "Field `BSVLD` writer - B-session valid"]
pub type BsvldW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Session request success"]
    #[inline(always)]
    pub fn srqscs(&self) -> SrqscsR {
        SrqscsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Session request"]
    #[inline(always)]
    pub fn srq(&self) -> SrqR {
        SrqR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 8 - Host negotiation success"]
    #[inline(always)]
    pub fn hngscs(&self) -> HngscsR {
        HngscsR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - HNP request"]
    #[inline(always)]
    pub fn hnprq(&self) -> HnprqR {
        HnprqR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Host set HNP enable"]
    #[inline(always)]
    pub fn hshnpen(&self) -> HshnpenR {
        HshnpenR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Device HNP enabled"]
    #[inline(always)]
    pub fn dhnpen(&self) -> DhnpenR {
        DhnpenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 16 - Connector ID status"]
    #[inline(always)]
    pub fn cidsts(&self) -> CidstsR {
        CidstsR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Long/short debounce time"]
    #[inline(always)]
    pub fn dbct(&self) -> DbctR {
        DbctR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - A-session valid"]
    #[inline(always)]
    pub fn asvld(&self) -> AsvldR {
        AsvldR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - B-session valid"]
    #[inline(always)]
    pub fn bsvld(&self) -> BsvldR {
        BsvldR::new(((self.bits >> 19) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Session request success"]
    #[inline(always)]
    #[must_use]
    pub fn srqscs(&mut self) -> SrqscsW<FsGotgctlSpec> {
        SrqscsW::new(self, 0)
    }
    #[doc = "Bit 1 - Session request"]
    #[inline(always)]
    #[must_use]
    pub fn srq(&mut self) -> SrqW<FsGotgctlSpec> {
        SrqW::new(self, 1)
    }
    #[doc = "Bit 8 - Host negotiation success"]
    #[inline(always)]
    #[must_use]
    pub fn hngscs(&mut self) -> HngscsW<FsGotgctlSpec> {
        HngscsW::new(self, 8)
    }
    #[doc = "Bit 9 - HNP request"]
    #[inline(always)]
    #[must_use]
    pub fn hnprq(&mut self) -> HnprqW<FsGotgctlSpec> {
        HnprqW::new(self, 9)
    }
    #[doc = "Bit 10 - Host set HNP enable"]
    #[inline(always)]
    #[must_use]
    pub fn hshnpen(&mut self) -> HshnpenW<FsGotgctlSpec> {
        HshnpenW::new(self, 10)
    }
    #[doc = "Bit 11 - Device HNP enabled"]
    #[inline(always)]
    #[must_use]
    pub fn dhnpen(&mut self) -> DhnpenW<FsGotgctlSpec> {
        DhnpenW::new(self, 11)
    }
    #[doc = "Bit 16 - Connector ID status"]
    #[inline(always)]
    #[must_use]
    pub fn cidsts(&mut self) -> CidstsW<FsGotgctlSpec> {
        CidstsW::new(self, 16)
    }
    #[doc = "Bit 17 - Long/short debounce time"]
    #[inline(always)]
    #[must_use]
    pub fn dbct(&mut self) -> DbctW<FsGotgctlSpec> {
        DbctW::new(self, 17)
    }
    #[doc = "Bit 18 - A-session valid"]
    #[inline(always)]
    #[must_use]
    pub fn asvld(&mut self) -> AsvldW<FsGotgctlSpec> {
        AsvldW::new(self, 18)
    }
    #[doc = "Bit 19 - B-session valid"]
    #[inline(always)]
    #[must_use]
    pub fn bsvld(&mut self) -> BsvldW<FsGotgctlSpec> {
        BsvldW::new(self, 19)
    }
}
#[doc = "OTG_FS control and status register (OTG_FS_GOTGCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_gotgctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_gotgctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsGotgctlSpec;
impl crate::RegisterSpec for FsGotgctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`fs_gotgctl::R`](R) reader structure"]
impl crate::Readable for FsGotgctlSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_gotgctl::W`](W) writer structure"]
impl crate::Writable for FsGotgctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_GOTGCTL to value 0x0800"]
impl crate::Resettable for FsGotgctlSpec {
    const RESET_VALUE: u32 = 0x0800;
}
