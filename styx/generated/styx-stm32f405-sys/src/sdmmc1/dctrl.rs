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
#[doc = "Register `DCTRL` reader"]
pub type R = crate::R<DctrlSpec>;
#[doc = "Register `DCTRL` writer"]
pub type W = crate::W<DctrlSpec>;
#[doc = "Field `DTEN` reader - DTEN"]
pub type DtenR = crate::BitReader;
#[doc = "Field `DTEN` writer - DTEN"]
pub type DtenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DTDIR` reader - Data transfer direction selection"]
pub type DtdirR = crate::BitReader;
#[doc = "Field `DTDIR` writer - Data transfer direction selection"]
pub type DtdirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DTMODE` reader - Data transfer mode selection 1: Stream or SDIO multibyte data transfer"]
pub type DtmodeR = crate::BitReader;
#[doc = "Field `DTMODE` writer - Data transfer mode selection 1: Stream or SDIO multibyte data transfer"]
pub type DtmodeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMAEN` reader - DMA enable bit"]
pub type DmaenR = crate::BitReader;
#[doc = "Field `DMAEN` writer - DMA enable bit"]
pub type DmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBLOCKSIZE` reader - Data block size"]
pub type DblocksizeR = crate::FieldReader;
#[doc = "Field `DBLOCKSIZE` writer - Data block size"]
pub type DblocksizeW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `RWSTART` reader - Read wait start"]
pub type RwstartR = crate::BitReader;
#[doc = "Field `RWSTART` writer - Read wait start"]
pub type RwstartW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RWSTOP` reader - Read wait stop"]
pub type RwstopR = crate::BitReader;
#[doc = "Field `RWSTOP` writer - Read wait stop"]
pub type RwstopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RWMOD` reader - Read wait mode"]
pub type RwmodR = crate::BitReader;
#[doc = "Field `RWMOD` writer - Read wait mode"]
pub type RwmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDIOEN` reader - SD I/O enable functions"]
pub type SdioenR = crate::BitReader;
#[doc = "Field `SDIOEN` writer - SD I/O enable functions"]
pub type SdioenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - DTEN"]
    #[inline(always)]
    pub fn dten(&self) -> DtenR {
        DtenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Data transfer direction selection"]
    #[inline(always)]
    pub fn dtdir(&self) -> DtdirR {
        DtdirR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Data transfer mode selection 1: Stream or SDIO multibyte data transfer"]
    #[inline(always)]
    pub fn dtmode(&self) -> DtmodeR {
        DtmodeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - DMA enable bit"]
    #[inline(always)]
    pub fn dmaen(&self) -> DmaenR {
        DmaenR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:7 - Data block size"]
    #[inline(always)]
    pub fn dblocksize(&self) -> DblocksizeR {
        DblocksizeR::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bit 8 - Read wait start"]
    #[inline(always)]
    pub fn rwstart(&self) -> RwstartR {
        RwstartR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Read wait stop"]
    #[inline(always)]
    pub fn rwstop(&self) -> RwstopR {
        RwstopR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Read wait mode"]
    #[inline(always)]
    pub fn rwmod(&self) -> RwmodR {
        RwmodR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - SD I/O enable functions"]
    #[inline(always)]
    pub fn sdioen(&self) -> SdioenR {
        SdioenR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - DTEN"]
    #[inline(always)]
    #[must_use]
    pub fn dten(&mut self) -> DtenW<DctrlSpec> {
        DtenW::new(self, 0)
    }
    #[doc = "Bit 1 - Data transfer direction selection"]
    #[inline(always)]
    #[must_use]
    pub fn dtdir(&mut self) -> DtdirW<DctrlSpec> {
        DtdirW::new(self, 1)
    }
    #[doc = "Bit 2 - Data transfer mode selection 1: Stream or SDIO multibyte data transfer"]
    #[inline(always)]
    #[must_use]
    pub fn dtmode(&mut self) -> DtmodeW<DctrlSpec> {
        DtmodeW::new(self, 2)
    }
    #[doc = "Bit 3 - DMA enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen(&mut self) -> DmaenW<DctrlSpec> {
        DmaenW::new(self, 3)
    }
    #[doc = "Bits 4:7 - Data block size"]
    #[inline(always)]
    #[must_use]
    pub fn dblocksize(&mut self) -> DblocksizeW<DctrlSpec> {
        DblocksizeW::new(self, 4)
    }
    #[doc = "Bit 8 - Read wait start"]
    #[inline(always)]
    #[must_use]
    pub fn rwstart(&mut self) -> RwstartW<DctrlSpec> {
        RwstartW::new(self, 8)
    }
    #[doc = "Bit 9 - Read wait stop"]
    #[inline(always)]
    #[must_use]
    pub fn rwstop(&mut self) -> RwstopW<DctrlSpec> {
        RwstopW::new(self, 9)
    }
    #[doc = "Bit 10 - Read wait mode"]
    #[inline(always)]
    #[must_use]
    pub fn rwmod(&mut self) -> RwmodW<DctrlSpec> {
        RwmodW::new(self, 10)
    }
    #[doc = "Bit 11 - SD I/O enable functions"]
    #[inline(always)]
    #[must_use]
    pub fn sdioen(&mut self) -> SdioenW<DctrlSpec> {
        SdioenW::new(self, 11)
    }
}
#[doc = "data control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DctrlSpec;
impl crate::RegisterSpec for DctrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`dctrl::R`](R) reader structure"]
impl crate::Readable for DctrlSpec {}
#[doc = "`write(|w| ..)` method takes [`dctrl::W`](W) writer structure"]
impl crate::Writable for DctrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DCTRL to value 0"]
impl crate::Resettable for DctrlSpec {
    const RESET_VALUE: u32 = 0;
}
