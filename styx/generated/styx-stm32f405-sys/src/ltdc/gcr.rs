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
#[doc = "Register `GCR` reader"]
pub type R = crate::R<GcrSpec>;
#[doc = "Register `GCR` writer"]
pub type W = crate::W<GcrSpec>;
#[doc = "Field `LTDCEN` reader - LCD-TFT controller enable bit"]
pub type LtdcenR = crate::BitReader;
#[doc = "Field `LTDCEN` writer - LCD-TFT controller enable bit"]
pub type LtdcenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBW` reader - Dither Blue Width"]
pub type DbwR = crate::FieldReader;
#[doc = "Field `DBW` writer - Dither Blue Width"]
pub type DbwW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `DGW` reader - Dither Green Width"]
pub type DgwR = crate::FieldReader;
#[doc = "Field `DGW` writer - Dither Green Width"]
pub type DgwW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `DRW` reader - Dither Red Width"]
pub type DrwR = crate::FieldReader;
#[doc = "Field `DRW` writer - Dither Red Width"]
pub type DrwW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `DEN` reader - Dither Enable"]
pub type DenR = crate::BitReader;
#[doc = "Field `DEN` writer - Dither Enable"]
pub type DenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PCPOL` reader - Pixel Clock Polarity"]
pub type PcpolR = crate::BitReader;
#[doc = "Field `PCPOL` writer - Pixel Clock Polarity"]
pub type PcpolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DEPOL` reader - Data Enable Polarity"]
pub type DepolR = crate::BitReader;
#[doc = "Field `DEPOL` writer - Data Enable Polarity"]
pub type DepolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSPOL` reader - Vertical Synchronization Polarity"]
pub type VspolR = crate::BitReader;
#[doc = "Field `VSPOL` writer - Vertical Synchronization Polarity"]
pub type VspolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSPOL` reader - Horizontal Synchronization Polarity"]
pub type HspolR = crate::BitReader;
#[doc = "Field `HSPOL` writer - Horizontal Synchronization Polarity"]
pub type HspolW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - LCD-TFT controller enable bit"]
    #[inline(always)]
    pub fn ltdcen(&self) -> LtdcenR {
        LtdcenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 4:6 - Dither Blue Width"]
    #[inline(always)]
    pub fn dbw(&self) -> DbwR {
        DbwR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bits 8:10 - Dither Green Width"]
    #[inline(always)]
    pub fn dgw(&self) -> DgwR {
        DgwR::new(((self.bits >> 8) & 7) as u8)
    }
    #[doc = "Bits 12:14 - Dither Red Width"]
    #[inline(always)]
    pub fn drw(&self) -> DrwR {
        DrwR::new(((self.bits >> 12) & 7) as u8)
    }
    #[doc = "Bit 16 - Dither Enable"]
    #[inline(always)]
    pub fn den(&self) -> DenR {
        DenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 28 - Pixel Clock Polarity"]
    #[inline(always)]
    pub fn pcpol(&self) -> PcpolR {
        PcpolR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Data Enable Polarity"]
    #[inline(always)]
    pub fn depol(&self) -> DepolR {
        DepolR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Vertical Synchronization Polarity"]
    #[inline(always)]
    pub fn vspol(&self) -> VspolR {
        VspolR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Horizontal Synchronization Polarity"]
    #[inline(always)]
    pub fn hspol(&self) -> HspolR {
        HspolR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - LCD-TFT controller enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn ltdcen(&mut self) -> LtdcenW<GcrSpec> {
        LtdcenW::new(self, 0)
    }
    #[doc = "Bits 4:6 - Dither Blue Width"]
    #[inline(always)]
    #[must_use]
    pub fn dbw(&mut self) -> DbwW<GcrSpec> {
        DbwW::new(self, 4)
    }
    #[doc = "Bits 8:10 - Dither Green Width"]
    #[inline(always)]
    #[must_use]
    pub fn dgw(&mut self) -> DgwW<GcrSpec> {
        DgwW::new(self, 8)
    }
    #[doc = "Bits 12:14 - Dither Red Width"]
    #[inline(always)]
    #[must_use]
    pub fn drw(&mut self) -> DrwW<GcrSpec> {
        DrwW::new(self, 12)
    }
    #[doc = "Bit 16 - Dither Enable"]
    #[inline(always)]
    #[must_use]
    pub fn den(&mut self) -> DenW<GcrSpec> {
        DenW::new(self, 16)
    }
    #[doc = "Bit 28 - Pixel Clock Polarity"]
    #[inline(always)]
    #[must_use]
    pub fn pcpol(&mut self) -> PcpolW<GcrSpec> {
        PcpolW::new(self, 28)
    }
    #[doc = "Bit 29 - Data Enable Polarity"]
    #[inline(always)]
    #[must_use]
    pub fn depol(&mut self) -> DepolW<GcrSpec> {
        DepolW::new(self, 29)
    }
    #[doc = "Bit 30 - Vertical Synchronization Polarity"]
    #[inline(always)]
    #[must_use]
    pub fn vspol(&mut self) -> VspolW<GcrSpec> {
        VspolW::new(self, 30)
    }
    #[doc = "Bit 31 - Horizontal Synchronization Polarity"]
    #[inline(always)]
    #[must_use]
    pub fn hspol(&mut self) -> HspolW<GcrSpec> {
        HspolW::new(self, 31)
    }
}
#[doc = "Global Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GcrSpec;
impl crate::RegisterSpec for GcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`gcr::R`](R) reader structure"]
impl crate::Readable for GcrSpec {}
#[doc = "`write(|w| ..)` method takes [`gcr::W`](W) writer structure"]
impl crate::Writable for GcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets GCR to value 0x2220"]
impl crate::Resettable for GcrSpec {
    const RESET_VALUE: u32 = 0x2220;
}
