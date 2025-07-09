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
#[doc = "Register `I2SCFGR` reader"]
pub type R = crate::R<I2scfgrSpec>;
#[doc = "Register `I2SCFGR` writer"]
pub type W = crate::W<I2scfgrSpec>;
#[doc = "Field `CHLEN` reader - Channel length (number of bits per audio channel)"]
pub type ChlenR = crate::BitReader;
#[doc = "Field `CHLEN` writer - Channel length (number of bits per audio channel)"]
pub type ChlenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DATLEN` reader - Data length to be transferred"]
pub type DatlenR = crate::FieldReader;
#[doc = "Field `DATLEN` writer - Data length to be transferred"]
pub type DatlenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `CKPOL` reader - Steady state clock polarity"]
pub type CkpolR = crate::BitReader;
#[doc = "Field `CKPOL` writer - Steady state clock polarity"]
pub type CkpolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2SSTD` reader - I2S standard selection"]
pub type I2sstdR = crate::FieldReader;
#[doc = "Field `I2SSTD` writer - I2S standard selection"]
pub type I2sstdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PCMSYNC` reader - PCM frame synchronization"]
pub type PcmsyncR = crate::BitReader;
#[doc = "Field `PCMSYNC` writer - PCM frame synchronization"]
pub type PcmsyncW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2SCFG` reader - I2S configuration mode"]
pub type I2scfgR = crate::FieldReader;
#[doc = "Field `I2SCFG` writer - I2S configuration mode"]
pub type I2scfgW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2SE` reader - I2S Enable"]
pub type I2seR = crate::BitReader;
#[doc = "Field `I2SE` writer - I2S Enable"]
pub type I2seW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2SMOD` reader - I2S mode selection"]
pub type I2smodR = crate::BitReader;
#[doc = "Field `I2SMOD` writer - I2S mode selection"]
pub type I2smodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ASTRTEN` reader - Asynchronous start enable"]
pub type AstrtenR = crate::BitReader;
#[doc = "Field `ASTRTEN` writer - Asynchronous start enable"]
pub type AstrtenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Channel length (number of bits per audio channel)"]
    #[inline(always)]
    pub fn chlen(&self) -> ChlenR {
        ChlenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Data length to be transferred"]
    #[inline(always)]
    pub fn datlen(&self) -> DatlenR {
        DatlenR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 3 - Steady state clock polarity"]
    #[inline(always)]
    pub fn ckpol(&self) -> CkpolR {
        CkpolR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:5 - I2S standard selection"]
    #[inline(always)]
    pub fn i2sstd(&self) -> I2sstdR {
        I2sstdR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bit 7 - PCM frame synchronization"]
    #[inline(always)]
    pub fn pcmsync(&self) -> PcmsyncR {
        PcmsyncR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:9 - I2S configuration mode"]
    #[inline(always)]
    pub fn i2scfg(&self) -> I2scfgR {
        I2scfgR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bit 10 - I2S Enable"]
    #[inline(always)]
    pub fn i2se(&self) -> I2seR {
        I2seR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - I2S mode selection"]
    #[inline(always)]
    pub fn i2smod(&self) -> I2smodR {
        I2smodR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Asynchronous start enable"]
    #[inline(always)]
    pub fn astrten(&self) -> AstrtenR {
        AstrtenR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Channel length (number of bits per audio channel)"]
    #[inline(always)]
    #[must_use]
    pub fn chlen(&mut self) -> ChlenW<I2scfgrSpec> {
        ChlenW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Data length to be transferred"]
    #[inline(always)]
    #[must_use]
    pub fn datlen(&mut self) -> DatlenW<I2scfgrSpec> {
        DatlenW::new(self, 1)
    }
    #[doc = "Bit 3 - Steady state clock polarity"]
    #[inline(always)]
    #[must_use]
    pub fn ckpol(&mut self) -> CkpolW<I2scfgrSpec> {
        CkpolW::new(self, 3)
    }
    #[doc = "Bits 4:5 - I2S standard selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2sstd(&mut self) -> I2sstdW<I2scfgrSpec> {
        I2sstdW::new(self, 4)
    }
    #[doc = "Bit 7 - PCM frame synchronization"]
    #[inline(always)]
    #[must_use]
    pub fn pcmsync(&mut self) -> PcmsyncW<I2scfgrSpec> {
        PcmsyncW::new(self, 7)
    }
    #[doc = "Bits 8:9 - I2S configuration mode"]
    #[inline(always)]
    #[must_use]
    pub fn i2scfg(&mut self) -> I2scfgW<I2scfgrSpec> {
        I2scfgW::new(self, 8)
    }
    #[doc = "Bit 10 - I2S Enable"]
    #[inline(always)]
    #[must_use]
    pub fn i2se(&mut self) -> I2seW<I2scfgrSpec> {
        I2seW::new(self, 10)
    }
    #[doc = "Bit 11 - I2S mode selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2smod(&mut self) -> I2smodW<I2scfgrSpec> {
        I2smodW::new(self, 11)
    }
    #[doc = "Bit 12 - Asynchronous start enable"]
    #[inline(always)]
    #[must_use]
    pub fn astrten(&mut self) -> AstrtenW<I2scfgrSpec> {
        AstrtenW::new(self, 12)
    }
}
#[doc = "I2S configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`i2scfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`i2scfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct I2scfgrSpec;
impl crate::RegisterSpec for I2scfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`i2scfgr::R`](R) reader structure"]
impl crate::Readable for I2scfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`i2scfgr::W`](W) writer structure"]
impl crate::Writable for I2scfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets I2SCFGR to value 0"]
impl crate::Resettable for I2scfgrSpec {
    const RESET_VALUE: u32 = 0;
}
