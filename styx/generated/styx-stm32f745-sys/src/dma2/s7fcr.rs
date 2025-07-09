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
#[doc = "Register `S7FCR` reader"]
pub type R = crate::R<S7fcrSpec>;
#[doc = "Register `S7FCR` writer"]
pub type W = crate::W<S7fcrSpec>;
#[doc = "Field `FTH` reader - FIFO threshold selection"]
pub type FthR = crate::FieldReader;
#[doc = "Field `FTH` writer - FIFO threshold selection"]
pub type FthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `DMDIS` reader - Direct mode disable"]
pub type DmdisR = crate::BitReader;
#[doc = "Field `DMDIS` writer - Direct mode disable"]
pub type DmdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FS` reader - FIFO status"]
pub type FsR = crate::FieldReader;
#[doc = "Field `FS` writer - FIFO status"]
pub type FsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `FEIE` reader - FIFO error interrupt enable"]
pub type FeieR = crate::BitReader;
#[doc = "Field `FEIE` writer - FIFO error interrupt enable"]
pub type FeieW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - FIFO threshold selection"]
    #[inline(always)]
    pub fn fth(&self) -> FthR {
        FthR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - Direct mode disable"]
    #[inline(always)]
    pub fn dmdis(&self) -> DmdisR {
        DmdisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:5 - FIFO status"]
    #[inline(always)]
    pub fn fs(&self) -> FsR {
        FsR::new(((self.bits >> 3) & 7) as u8)
    }
    #[doc = "Bit 7 - FIFO error interrupt enable"]
    #[inline(always)]
    pub fn feie(&self) -> FeieR {
        FeieR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - FIFO threshold selection"]
    #[inline(always)]
    #[must_use]
    pub fn fth(&mut self) -> FthW<S7fcrSpec> {
        FthW::new(self, 0)
    }
    #[doc = "Bit 2 - Direct mode disable"]
    #[inline(always)]
    #[must_use]
    pub fn dmdis(&mut self) -> DmdisW<S7fcrSpec> {
        DmdisW::new(self, 2)
    }
    #[doc = "Bits 3:5 - FIFO status"]
    #[inline(always)]
    #[must_use]
    pub fn fs(&mut self) -> FsW<S7fcrSpec> {
        FsW::new(self, 3)
    }
    #[doc = "Bit 7 - FIFO error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn feie(&mut self) -> FeieW<S7fcrSpec> {
        FeieW::new(self, 7)
    }
}
#[doc = "stream x FIFO control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s7fcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s7fcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S7fcrSpec;
impl crate::RegisterSpec for S7fcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 204u64;
}
#[doc = "`read()` method returns [`s7fcr::R`](R) reader structure"]
impl crate::Readable for S7fcrSpec {}
#[doc = "`write(|w| ..)` method takes [`s7fcr::W`](W) writer structure"]
impl crate::Writable for S7fcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S7FCR to value 0x21"]
impl crate::Resettable for S7fcrSpec {
    const RESET_VALUE: u32 = 0x21;
}
