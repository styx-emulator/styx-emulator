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
#[doc = "Register `OTG_FS_GOTGCTL` reader"]
pub type R = crate::R<OtgFsGotgctlSpec>;
#[doc = "Register `OTG_FS_GOTGCTL` writer"]
pub type W = crate::W<OtgFsGotgctlSpec>;
#[doc = "Field `SRQSCS` reader - Session request success"]
pub type SrqscsR = crate::BitReader;
#[doc = "Field `SRQSCS` writer - Session request success"]
pub type SrqscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRQ` reader - Session request"]
pub type SrqR = crate::BitReader;
#[doc = "Field `SRQ` writer - Session request"]
pub type SrqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBVALOEN` reader - VBUS valid override enable"]
pub type VbvaloenR = crate::BitReader;
#[doc = "Field `VBVALOEN` writer - VBUS valid override enable"]
pub type VbvaloenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBVALOVAL` reader - VBUS valid override value"]
pub type VbvalovalR = crate::BitReader;
#[doc = "Field `VBVALOVAL` writer - VBUS valid override value"]
pub type VbvalovalW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AVALOEN` reader - A-peripheral session valid override enable"]
pub type AvaloenR = crate::BitReader;
#[doc = "Field `AVALOEN` writer - A-peripheral session valid override enable"]
pub type AvaloenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AVALOVAL` reader - A-peripheral session valid override value"]
pub type AvalovalR = crate::BitReader;
#[doc = "Field `AVALOVAL` writer - A-peripheral session valid override value"]
pub type AvalovalW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BVALOEN` reader - B-peripheral session valid override enable"]
pub type BvaloenR = crate::BitReader;
#[doc = "Field `BVALOEN` writer - B-peripheral session valid override enable"]
pub type BvaloenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BVALOVAL` reader - B-peripheral session valid override value"]
pub type BvalovalR = crate::BitReader;
#[doc = "Field `BVALOVAL` writer - B-peripheral session valid override value"]
pub type BvalovalW<'a, REG> = crate::BitWriter<'a, REG>;
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
#[doc = "Field `EHEN` reader - Embedded host enable"]
pub type EhenR = crate::BitReader;
#[doc = "Field `EHEN` writer - Embedded host enable"]
pub type EhenW<'a, REG> = crate::BitWriter<'a, REG>;
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
#[doc = "Field `OTGVER` reader - OTG version"]
pub type OtgverR = crate::BitReader;
#[doc = "Field `OTGVER` writer - OTG version"]
pub type OtgverW<'a, REG> = crate::BitWriter<'a, REG>;
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
    #[doc = "Bit 2 - VBUS valid override enable"]
    #[inline(always)]
    pub fn vbvaloen(&self) -> VbvaloenR {
        VbvaloenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - VBUS valid override value"]
    #[inline(always)]
    pub fn vbvaloval(&self) -> VbvalovalR {
        VbvalovalR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - A-peripheral session valid override enable"]
    #[inline(always)]
    pub fn avaloen(&self) -> AvaloenR {
        AvaloenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - A-peripheral session valid override value"]
    #[inline(always)]
    pub fn avaloval(&self) -> AvalovalR {
        AvalovalR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - B-peripheral session valid override enable"]
    #[inline(always)]
    pub fn bvaloen(&self) -> BvaloenR {
        BvaloenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - B-peripheral session valid override value"]
    #[inline(always)]
    pub fn bvaloval(&self) -> BvalovalR {
        BvalovalR::new(((self.bits >> 7) & 1) != 0)
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
    #[doc = "Bit 12 - Embedded host enable"]
    #[inline(always)]
    pub fn ehen(&self) -> EhenR {
        EhenR::new(((self.bits >> 12) & 1) != 0)
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
    #[doc = "Bit 20 - OTG version"]
    #[inline(always)]
    pub fn otgver(&self) -> OtgverR {
        OtgverR::new(((self.bits >> 20) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Session request success"]
    #[inline(always)]
    #[must_use]
    pub fn srqscs(&mut self) -> SrqscsW<OtgFsGotgctlSpec> {
        SrqscsW::new(self, 0)
    }
    #[doc = "Bit 1 - Session request"]
    #[inline(always)]
    #[must_use]
    pub fn srq(&mut self) -> SrqW<OtgFsGotgctlSpec> {
        SrqW::new(self, 1)
    }
    #[doc = "Bit 2 - VBUS valid override enable"]
    #[inline(always)]
    #[must_use]
    pub fn vbvaloen(&mut self) -> VbvaloenW<OtgFsGotgctlSpec> {
        VbvaloenW::new(self, 2)
    }
    #[doc = "Bit 3 - VBUS valid override value"]
    #[inline(always)]
    #[must_use]
    pub fn vbvaloval(&mut self) -> VbvalovalW<OtgFsGotgctlSpec> {
        VbvalovalW::new(self, 3)
    }
    #[doc = "Bit 4 - A-peripheral session valid override enable"]
    #[inline(always)]
    #[must_use]
    pub fn avaloen(&mut self) -> AvaloenW<OtgFsGotgctlSpec> {
        AvaloenW::new(self, 4)
    }
    #[doc = "Bit 5 - A-peripheral session valid override value"]
    #[inline(always)]
    #[must_use]
    pub fn avaloval(&mut self) -> AvalovalW<OtgFsGotgctlSpec> {
        AvalovalW::new(self, 5)
    }
    #[doc = "Bit 6 - B-peripheral session valid override enable"]
    #[inline(always)]
    #[must_use]
    pub fn bvaloen(&mut self) -> BvaloenW<OtgFsGotgctlSpec> {
        BvaloenW::new(self, 6)
    }
    #[doc = "Bit 7 - B-peripheral session valid override value"]
    #[inline(always)]
    #[must_use]
    pub fn bvaloval(&mut self) -> BvalovalW<OtgFsGotgctlSpec> {
        BvalovalW::new(self, 7)
    }
    #[doc = "Bit 8 - Host negotiation success"]
    #[inline(always)]
    #[must_use]
    pub fn hngscs(&mut self) -> HngscsW<OtgFsGotgctlSpec> {
        HngscsW::new(self, 8)
    }
    #[doc = "Bit 9 - HNP request"]
    #[inline(always)]
    #[must_use]
    pub fn hnprq(&mut self) -> HnprqW<OtgFsGotgctlSpec> {
        HnprqW::new(self, 9)
    }
    #[doc = "Bit 10 - Host set HNP enable"]
    #[inline(always)]
    #[must_use]
    pub fn hshnpen(&mut self) -> HshnpenW<OtgFsGotgctlSpec> {
        HshnpenW::new(self, 10)
    }
    #[doc = "Bit 11 - Device HNP enabled"]
    #[inline(always)]
    #[must_use]
    pub fn dhnpen(&mut self) -> DhnpenW<OtgFsGotgctlSpec> {
        DhnpenW::new(self, 11)
    }
    #[doc = "Bit 12 - Embedded host enable"]
    #[inline(always)]
    #[must_use]
    pub fn ehen(&mut self) -> EhenW<OtgFsGotgctlSpec> {
        EhenW::new(self, 12)
    }
    #[doc = "Bit 16 - Connector ID status"]
    #[inline(always)]
    #[must_use]
    pub fn cidsts(&mut self) -> CidstsW<OtgFsGotgctlSpec> {
        CidstsW::new(self, 16)
    }
    #[doc = "Bit 17 - Long/short debounce time"]
    #[inline(always)]
    #[must_use]
    pub fn dbct(&mut self) -> DbctW<OtgFsGotgctlSpec> {
        DbctW::new(self, 17)
    }
    #[doc = "Bit 18 - A-session valid"]
    #[inline(always)]
    #[must_use]
    pub fn asvld(&mut self) -> AsvldW<OtgFsGotgctlSpec> {
        AsvldW::new(self, 18)
    }
    #[doc = "Bit 19 - B-session valid"]
    #[inline(always)]
    #[must_use]
    pub fn bsvld(&mut self) -> BsvldW<OtgFsGotgctlSpec> {
        BsvldW::new(self, 19)
    }
    #[doc = "Bit 20 - OTG version"]
    #[inline(always)]
    #[must_use]
    pub fn otgver(&mut self) -> OtgverW<OtgFsGotgctlSpec> {
        OtgverW::new(self, 20)
    }
}
#[doc = "OTG_FS control and status register (OTG_FS_GOTGCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gotgctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gotgctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGotgctlSpec;
impl crate::RegisterSpec for OtgFsGotgctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`otg_fs_gotgctl::R`](R) reader structure"]
impl crate::Readable for OtgFsGotgctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gotgctl::W`](W) writer structure"]
impl crate::Writable for OtgFsGotgctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GOTGCTL to value 0x0800"]
impl crate::Resettable for OtgFsGotgctlSpec {
    const RESET_VALUE: u32 = 0x0800;
}
