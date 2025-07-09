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
#[doc = "Register `MACCR` reader"]
pub type R = crate::R<MaccrSpec>;
#[doc = "Register `MACCR` writer"]
pub type W = crate::W<MaccrSpec>;
#[doc = "Field `RE` reader - RE"]
pub type ReR = crate::BitReader;
#[doc = "Field `RE` writer - RE"]
pub type ReW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TE` reader - TE"]
pub type TeR = crate::BitReader;
#[doc = "Field `TE` writer - TE"]
pub type TeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DC` reader - DC"]
pub type DcR = crate::BitReader;
#[doc = "Field `DC` writer - DC"]
pub type DcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BL` reader - BL"]
pub type BlR = crate::FieldReader;
#[doc = "Field `BL` writer - BL"]
pub type BlW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `APCS` reader - APCS"]
pub type ApcsR = crate::BitReader;
#[doc = "Field `APCS` writer - APCS"]
pub type ApcsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RD` reader - RD"]
pub type RdR = crate::BitReader;
#[doc = "Field `RD` writer - RD"]
pub type RdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IPCO` reader - IPCO"]
pub type IpcoR = crate::BitReader;
#[doc = "Field `IPCO` writer - IPCO"]
pub type IpcoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DM` reader - DM"]
pub type DmR = crate::BitReader;
#[doc = "Field `DM` writer - DM"]
pub type DmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LM` reader - LM"]
pub type LmR = crate::BitReader;
#[doc = "Field `LM` writer - LM"]
pub type LmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ROD` reader - ROD"]
pub type RodR = crate::BitReader;
#[doc = "Field `ROD` writer - ROD"]
pub type RodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FES` reader - FES"]
pub type FesR = crate::BitReader;
#[doc = "Field `FES` writer - FES"]
pub type FesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSD` reader - CSD"]
pub type CsdR = crate::BitReader;
#[doc = "Field `CSD` writer - CSD"]
pub type CsdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IFG` reader - IFG"]
pub type IfgR = crate::FieldReader;
#[doc = "Field `IFG` writer - IFG"]
pub type IfgW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `JD` reader - JD"]
pub type JdR = crate::BitReader;
#[doc = "Field `JD` writer - JD"]
pub type JdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WD` reader - WD"]
pub type WdR = crate::BitReader;
#[doc = "Field `WD` writer - WD"]
pub type WdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSTF` reader - CSTF"]
pub type CstfR = crate::BitReader;
#[doc = "Field `CSTF` writer - CSTF"]
pub type CstfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 2 - RE"]
    #[inline(always)]
    pub fn re(&self) -> ReR {
        ReR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - TE"]
    #[inline(always)]
    pub fn te(&self) -> TeR {
        TeR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - DC"]
    #[inline(always)]
    pub fn dc(&self) -> DcR {
        DcR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:6 - BL"]
    #[inline(always)]
    pub fn bl(&self) -> BlR {
        BlR::new(((self.bits >> 5) & 3) as u8)
    }
    #[doc = "Bit 7 - APCS"]
    #[inline(always)]
    pub fn apcs(&self) -> ApcsR {
        ApcsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 9 - RD"]
    #[inline(always)]
    pub fn rd(&self) -> RdR {
        RdR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - IPCO"]
    #[inline(always)]
    pub fn ipco(&self) -> IpcoR {
        IpcoR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - DM"]
    #[inline(always)]
    pub fn dm(&self) -> DmR {
        DmR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - LM"]
    #[inline(always)]
    pub fn lm(&self) -> LmR {
        LmR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - ROD"]
    #[inline(always)]
    pub fn rod(&self) -> RodR {
        RodR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - FES"]
    #[inline(always)]
    pub fn fes(&self) -> FesR {
        FesR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - CSD"]
    #[inline(always)]
    pub fn csd(&self) -> CsdR {
        CsdR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:19 - IFG"]
    #[inline(always)]
    pub fn ifg(&self) -> IfgR {
        IfgR::new(((self.bits >> 17) & 7) as u8)
    }
    #[doc = "Bit 22 - JD"]
    #[inline(always)]
    pub fn jd(&self) -> JdR {
        JdR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - WD"]
    #[inline(always)]
    pub fn wd(&self) -> WdR {
        WdR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 25 - CSTF"]
    #[inline(always)]
    pub fn cstf(&self) -> CstfR {
        CstfR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 2 - RE"]
    #[inline(always)]
    #[must_use]
    pub fn re(&mut self) -> ReW<MaccrSpec> {
        ReW::new(self, 2)
    }
    #[doc = "Bit 3 - TE"]
    #[inline(always)]
    #[must_use]
    pub fn te(&mut self) -> TeW<MaccrSpec> {
        TeW::new(self, 3)
    }
    #[doc = "Bit 4 - DC"]
    #[inline(always)]
    #[must_use]
    pub fn dc(&mut self) -> DcW<MaccrSpec> {
        DcW::new(self, 4)
    }
    #[doc = "Bits 5:6 - BL"]
    #[inline(always)]
    #[must_use]
    pub fn bl(&mut self) -> BlW<MaccrSpec> {
        BlW::new(self, 5)
    }
    #[doc = "Bit 7 - APCS"]
    #[inline(always)]
    #[must_use]
    pub fn apcs(&mut self) -> ApcsW<MaccrSpec> {
        ApcsW::new(self, 7)
    }
    #[doc = "Bit 9 - RD"]
    #[inline(always)]
    #[must_use]
    pub fn rd(&mut self) -> RdW<MaccrSpec> {
        RdW::new(self, 9)
    }
    #[doc = "Bit 10 - IPCO"]
    #[inline(always)]
    #[must_use]
    pub fn ipco(&mut self) -> IpcoW<MaccrSpec> {
        IpcoW::new(self, 10)
    }
    #[doc = "Bit 11 - DM"]
    #[inline(always)]
    #[must_use]
    pub fn dm(&mut self) -> DmW<MaccrSpec> {
        DmW::new(self, 11)
    }
    #[doc = "Bit 12 - LM"]
    #[inline(always)]
    #[must_use]
    pub fn lm(&mut self) -> LmW<MaccrSpec> {
        LmW::new(self, 12)
    }
    #[doc = "Bit 13 - ROD"]
    #[inline(always)]
    #[must_use]
    pub fn rod(&mut self) -> RodW<MaccrSpec> {
        RodW::new(self, 13)
    }
    #[doc = "Bit 14 - FES"]
    #[inline(always)]
    #[must_use]
    pub fn fes(&mut self) -> FesW<MaccrSpec> {
        FesW::new(self, 14)
    }
    #[doc = "Bit 16 - CSD"]
    #[inline(always)]
    #[must_use]
    pub fn csd(&mut self) -> CsdW<MaccrSpec> {
        CsdW::new(self, 16)
    }
    #[doc = "Bits 17:19 - IFG"]
    #[inline(always)]
    #[must_use]
    pub fn ifg(&mut self) -> IfgW<MaccrSpec> {
        IfgW::new(self, 17)
    }
    #[doc = "Bit 22 - JD"]
    #[inline(always)]
    #[must_use]
    pub fn jd(&mut self) -> JdW<MaccrSpec> {
        JdW::new(self, 22)
    }
    #[doc = "Bit 23 - WD"]
    #[inline(always)]
    #[must_use]
    pub fn wd(&mut self) -> WdW<MaccrSpec> {
        WdW::new(self, 23)
    }
    #[doc = "Bit 25 - CSTF"]
    #[inline(always)]
    #[must_use]
    pub fn cstf(&mut self) -> CstfW<MaccrSpec> {
        CstfW::new(self, 25)
    }
}
#[doc = "Ethernet MAC configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`maccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`maccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MaccrSpec;
impl crate::RegisterSpec for MaccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`maccr::R`](R) reader structure"]
impl crate::Readable for MaccrSpec {}
#[doc = "`write(|w| ..)` method takes [`maccr::W`](W) writer structure"]
impl crate::Writable for MaccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACCR to value 0x8000"]
impl crate::Resettable for MaccrSpec {
    const RESET_VALUE: u32 = 0x8000;
}
