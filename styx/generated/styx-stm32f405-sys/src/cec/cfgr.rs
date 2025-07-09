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
#[doc = "Register `CFGR` reader"]
pub type R = crate::R<CfgrSpec>;
#[doc = "Register `CFGR` writer"]
pub type W = crate::W<CfgrSpec>;
#[doc = "Field `SFT` reader - Signal Free Time"]
pub type SftR = crate::FieldReader;
#[doc = "Field `SFT` writer - Signal Free Time"]
pub type SftW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `RXTOL` reader - Rx-Tolerance"]
pub type RxtolR = crate::BitReader;
#[doc = "Field `RXTOL` writer - Rx-Tolerance"]
pub type RxtolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BRESTP` reader - Rx-stop on bit rising error"]
pub type BrestpR = crate::BitReader;
#[doc = "Field `BRESTP` writer - Rx-stop on bit rising error"]
pub type BrestpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BREGEN` reader - Generate error-bit on bit rising error"]
pub type BregenR = crate::BitReader;
#[doc = "Field `BREGEN` writer - Generate error-bit on bit rising error"]
pub type BregenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LBPEGEN` reader - Generate Error-Bit on Long Bit Period Error"]
pub type LbpegenR = crate::BitReader;
#[doc = "Field `LBPEGEN` writer - Generate Error-Bit on Long Bit Period Error"]
pub type LbpegenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BRDNOGEN` reader - Avoid Error-Bit Generation in Broadcast"]
pub type BrdnogenR = crate::BitReader;
#[doc = "Field `BRDNOGEN` writer - Avoid Error-Bit Generation in Broadcast"]
pub type BrdnogenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SFTOP` reader - SFT Option Bit"]
pub type SftopR = crate::BitReader;
#[doc = "Field `SFTOP` writer - SFT Option Bit"]
pub type SftopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OAR` reader - Own addresses configuration"]
pub type OarR = crate::FieldReader<u16>;
#[doc = "Field `OAR` writer - Own addresses configuration"]
pub type OarW<'a, REG> = crate::FieldWriter<'a, REG, 15, u16>;
#[doc = "Field `LSTN` reader - Listen mode"]
pub type LstnR = crate::BitReader;
#[doc = "Field `LSTN` writer - Listen mode"]
pub type LstnW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - Signal Free Time"]
    #[inline(always)]
    pub fn sft(&self) -> SftR {
        SftR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 3 - Rx-Tolerance"]
    #[inline(always)]
    pub fn rxtol(&self) -> RxtolR {
        RxtolR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Rx-stop on bit rising error"]
    #[inline(always)]
    pub fn brestp(&self) -> BrestpR {
        BrestpR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Generate error-bit on bit rising error"]
    #[inline(always)]
    pub fn bregen(&self) -> BregenR {
        BregenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Generate Error-Bit on Long Bit Period Error"]
    #[inline(always)]
    pub fn lbpegen(&self) -> LbpegenR {
        LbpegenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Avoid Error-Bit Generation in Broadcast"]
    #[inline(always)]
    pub fn brdnogen(&self) -> BrdnogenR {
        BrdnogenR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - SFT Option Bit"]
    #[inline(always)]
    pub fn sftop(&self) -> SftopR {
        SftopR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bits 16:30 - Own addresses configuration"]
    #[inline(always)]
    pub fn oar(&self) -> OarR {
        OarR::new(((self.bits >> 16) & 0x7fff) as u16)
    }
    #[doc = "Bit 31 - Listen mode"]
    #[inline(always)]
    pub fn lstn(&self) -> LstnR {
        LstnR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - Signal Free Time"]
    #[inline(always)]
    #[must_use]
    pub fn sft(&mut self) -> SftW<CfgrSpec> {
        SftW::new(self, 0)
    }
    #[doc = "Bit 3 - Rx-Tolerance"]
    #[inline(always)]
    #[must_use]
    pub fn rxtol(&mut self) -> RxtolW<CfgrSpec> {
        RxtolW::new(self, 3)
    }
    #[doc = "Bit 4 - Rx-stop on bit rising error"]
    #[inline(always)]
    #[must_use]
    pub fn brestp(&mut self) -> BrestpW<CfgrSpec> {
        BrestpW::new(self, 4)
    }
    #[doc = "Bit 5 - Generate error-bit on bit rising error"]
    #[inline(always)]
    #[must_use]
    pub fn bregen(&mut self) -> BregenW<CfgrSpec> {
        BregenW::new(self, 5)
    }
    #[doc = "Bit 6 - Generate Error-Bit on Long Bit Period Error"]
    #[inline(always)]
    #[must_use]
    pub fn lbpegen(&mut self) -> LbpegenW<CfgrSpec> {
        LbpegenW::new(self, 6)
    }
    #[doc = "Bit 7 - Avoid Error-Bit Generation in Broadcast"]
    #[inline(always)]
    #[must_use]
    pub fn brdnogen(&mut self) -> BrdnogenW<CfgrSpec> {
        BrdnogenW::new(self, 7)
    }
    #[doc = "Bit 8 - SFT Option Bit"]
    #[inline(always)]
    #[must_use]
    pub fn sftop(&mut self) -> SftopW<CfgrSpec> {
        SftopW::new(self, 8)
    }
    #[doc = "Bits 16:30 - Own addresses configuration"]
    #[inline(always)]
    #[must_use]
    pub fn oar(&mut self) -> OarW<CfgrSpec> {
        OarW::new(self, 16)
    }
    #[doc = "Bit 31 - Listen mode"]
    #[inline(always)]
    #[must_use]
    pub fn lstn(&mut self) -> LstnW<CfgrSpec> {
        LstnW::new(self, 31)
    }
}
#[doc = "configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CfgrSpec;
impl crate::RegisterSpec for CfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`cfgr::R`](R) reader structure"]
impl crate::Readable for CfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`cfgr::W`](W) writer structure"]
impl crate::Writable for CfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CFGR to value 0"]
impl crate::Resettable for CfgrSpec {
    const RESET_VALUE: u32 = 0;
}
