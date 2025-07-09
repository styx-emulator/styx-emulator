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
#[doc = "Register `MACFFR` reader"]
pub type R = crate::R<MacffrSpec>;
#[doc = "Register `MACFFR` writer"]
pub type W = crate::W<MacffrSpec>;
#[doc = "Field `PM` reader - PM"]
pub type PmR = crate::BitReader;
#[doc = "Field `PM` writer - PM"]
pub type PmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HU` reader - HU"]
pub type HuR = crate::BitReader;
#[doc = "Field `HU` writer - HU"]
pub type HuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HM` reader - HM"]
pub type HmR = crate::BitReader;
#[doc = "Field `HM` writer - HM"]
pub type HmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DAIF` reader - DAIF"]
pub type DaifR = crate::BitReader;
#[doc = "Field `DAIF` writer - DAIF"]
pub type DaifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RAM` reader - RAM"]
pub type RamR = crate::BitReader;
#[doc = "Field `RAM` writer - RAM"]
pub type RamW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BFD` reader - BFD"]
pub type BfdR = crate::BitReader;
#[doc = "Field `BFD` writer - BFD"]
pub type BfdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PCF` reader - PCF"]
pub type PcfR = crate::BitReader;
#[doc = "Field `PCF` writer - PCF"]
pub type PcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAIF` reader - SAIF"]
pub type SaifR = crate::BitReader;
#[doc = "Field `SAIF` writer - SAIF"]
pub type SaifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAF` reader - SAF"]
pub type SafR = crate::BitReader;
#[doc = "Field `SAF` writer - SAF"]
pub type SafW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HPF` reader - HPF"]
pub type HpfR = crate::BitReader;
#[doc = "Field `HPF` writer - HPF"]
pub type HpfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RA` reader - RA"]
pub type RaR = crate::BitReader;
#[doc = "Field `RA` writer - RA"]
pub type RaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - PM"]
    #[inline(always)]
    pub fn pm(&self) -> PmR {
        PmR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - HU"]
    #[inline(always)]
    pub fn hu(&self) -> HuR {
        HuR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - HM"]
    #[inline(always)]
    pub fn hm(&self) -> HmR {
        HmR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - DAIF"]
    #[inline(always)]
    pub fn daif(&self) -> DaifR {
        DaifR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - RAM"]
    #[inline(always)]
    pub fn ram(&self) -> RamR {
        RamR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - BFD"]
    #[inline(always)]
    pub fn bfd(&self) -> BfdR {
        BfdR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - PCF"]
    #[inline(always)]
    pub fn pcf(&self) -> PcfR {
        PcfR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - SAIF"]
    #[inline(always)]
    pub fn saif(&self) -> SaifR {
        SaifR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - SAF"]
    #[inline(always)]
    pub fn saf(&self) -> SafR {
        SafR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - HPF"]
    #[inline(always)]
    pub fn hpf(&self) -> HpfR {
        HpfR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 31 - RA"]
    #[inline(always)]
    pub fn ra(&self) -> RaR {
        RaR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - PM"]
    #[inline(always)]
    #[must_use]
    pub fn pm(&mut self) -> PmW<MacffrSpec> {
        PmW::new(self, 0)
    }
    #[doc = "Bit 1 - HU"]
    #[inline(always)]
    #[must_use]
    pub fn hu(&mut self) -> HuW<MacffrSpec> {
        HuW::new(self, 1)
    }
    #[doc = "Bit 2 - HM"]
    #[inline(always)]
    #[must_use]
    pub fn hm(&mut self) -> HmW<MacffrSpec> {
        HmW::new(self, 2)
    }
    #[doc = "Bit 3 - DAIF"]
    #[inline(always)]
    #[must_use]
    pub fn daif(&mut self) -> DaifW<MacffrSpec> {
        DaifW::new(self, 3)
    }
    #[doc = "Bit 4 - RAM"]
    #[inline(always)]
    #[must_use]
    pub fn ram(&mut self) -> RamW<MacffrSpec> {
        RamW::new(self, 4)
    }
    #[doc = "Bit 5 - BFD"]
    #[inline(always)]
    #[must_use]
    pub fn bfd(&mut self) -> BfdW<MacffrSpec> {
        BfdW::new(self, 5)
    }
    #[doc = "Bit 6 - PCF"]
    #[inline(always)]
    #[must_use]
    pub fn pcf(&mut self) -> PcfW<MacffrSpec> {
        PcfW::new(self, 6)
    }
    #[doc = "Bit 7 - SAIF"]
    #[inline(always)]
    #[must_use]
    pub fn saif(&mut self) -> SaifW<MacffrSpec> {
        SaifW::new(self, 7)
    }
    #[doc = "Bit 8 - SAF"]
    #[inline(always)]
    #[must_use]
    pub fn saf(&mut self) -> SafW<MacffrSpec> {
        SafW::new(self, 8)
    }
    #[doc = "Bit 9 - HPF"]
    #[inline(always)]
    #[must_use]
    pub fn hpf(&mut self) -> HpfW<MacffrSpec> {
        HpfW::new(self, 9)
    }
    #[doc = "Bit 31 - RA"]
    #[inline(always)]
    #[must_use]
    pub fn ra(&mut self) -> RaW<MacffrSpec> {
        RaW::new(self, 31)
    }
}
#[doc = "Ethernet MAC frame filter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macffr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macffr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacffrSpec;
impl crate::RegisterSpec for MacffrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`macffr::R`](R) reader structure"]
impl crate::Readable for MacffrSpec {}
#[doc = "`write(|w| ..)` method takes [`macffr::W`](W) writer structure"]
impl crate::Writable for MacffrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACFFR to value 0"]
impl crate::Resettable for MacffrSpec {
    const RESET_VALUE: u32 = 0;
}
