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
#[doc = "Register `SAI_BFRCR` reader"]
pub type R = crate::R<SaiBfrcrSpec>;
#[doc = "Register `SAI_BFRCR` writer"]
pub type W = crate::W<SaiBfrcrSpec>;
#[doc = "Field `FRL` reader - Frame length"]
pub type FrlR = crate::FieldReader;
#[doc = "Field `FRL` writer - Frame length"]
pub type FrlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `FSALL` reader - Frame synchronization active level length"]
pub type FsallR = crate::FieldReader;
#[doc = "Field `FSALL` writer - Frame synchronization active level length"]
pub type FsallW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `FSDEF` reader - Frame synchronization definition"]
pub type FsdefR = crate::BitReader;
#[doc = "Field `FSDEF` writer - Frame synchronization definition"]
pub type FsdefW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FSPOL` reader - Frame synchronization polarity"]
pub type FspolR = crate::BitReader;
#[doc = "Field `FSPOL` writer - Frame synchronization polarity"]
pub type FspolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FSOFF` reader - Frame synchronization offset"]
pub type FsoffR = crate::BitReader;
#[doc = "Field `FSOFF` writer - Frame synchronization offset"]
pub type FsoffW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Frame length"]
    #[inline(always)]
    pub fn frl(&self) -> FrlR {
        FrlR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:14 - Frame synchronization active level length"]
    #[inline(always)]
    pub fn fsall(&self) -> FsallR {
        FsallR::new(((self.bits >> 8) & 0x7f) as u8)
    }
    #[doc = "Bit 16 - Frame synchronization definition"]
    #[inline(always)]
    pub fn fsdef(&self) -> FsdefR {
        FsdefR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Frame synchronization polarity"]
    #[inline(always)]
    pub fn fspol(&self) -> FspolR {
        FspolR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Frame synchronization offset"]
    #[inline(always)]
    pub fn fsoff(&self) -> FsoffR {
        FsoffR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Frame length"]
    #[inline(always)]
    #[must_use]
    pub fn frl(&mut self) -> FrlW<SaiBfrcrSpec> {
        FrlW::new(self, 0)
    }
    #[doc = "Bits 8:14 - Frame synchronization active level length"]
    #[inline(always)]
    #[must_use]
    pub fn fsall(&mut self) -> FsallW<SaiBfrcrSpec> {
        FsallW::new(self, 8)
    }
    #[doc = "Bit 16 - Frame synchronization definition"]
    #[inline(always)]
    #[must_use]
    pub fn fsdef(&mut self) -> FsdefW<SaiBfrcrSpec> {
        FsdefW::new(self, 16)
    }
    #[doc = "Bit 17 - Frame synchronization polarity"]
    #[inline(always)]
    #[must_use]
    pub fn fspol(&mut self) -> FspolW<SaiBfrcrSpec> {
        FspolW::new(self, 17)
    }
    #[doc = "Bit 18 - Frame synchronization offset"]
    #[inline(always)]
    #[must_use]
    pub fn fsoff(&mut self) -> FsoffW<SaiBfrcrSpec> {
        FsoffW::new(self, 18)
    }
}
#[doc = "SAI BFrame configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bfrcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bfrcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiBfrcrSpec;
impl crate::RegisterSpec for SaiBfrcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`sai_bfrcr::R`](R) reader structure"]
impl crate::Readable for SaiBfrcrSpec {}
#[doc = "`write(|w| ..)` method takes [`sai_bfrcr::W`](W) writer structure"]
impl crate::Writable for SaiBfrcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SAI_BFRCR to value 0x07"]
impl crate::Resettable for SaiBfrcrSpec {
    const RESET_VALUE: u32 = 0x07;
}
