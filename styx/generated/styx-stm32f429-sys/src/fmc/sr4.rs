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
#[doc = "Register `SR4` reader"]
pub type R = crate::R<Sr4Spec>;
#[doc = "Register `SR4` writer"]
pub type W = crate::W<Sr4Spec>;
#[doc = "Field `IRS` reader - IRS"]
pub type IrsR = crate::BitReader;
#[doc = "Field `IRS` writer - IRS"]
pub type IrsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ILS` reader - ILS"]
pub type IlsR = crate::BitReader;
#[doc = "Field `ILS` writer - ILS"]
pub type IlsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IFS` reader - IFS"]
pub type IfsR = crate::BitReader;
#[doc = "Field `IFS` writer - IFS"]
pub type IfsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IREN` reader - IREN"]
pub type IrenR = crate::BitReader;
#[doc = "Field `IREN` writer - IREN"]
pub type IrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ILEN` reader - ILEN"]
pub type IlenR = crate::BitReader;
#[doc = "Field `ILEN` writer - ILEN"]
pub type IlenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IFEN` reader - IFEN"]
pub type IfenR = crate::BitReader;
#[doc = "Field `IFEN` writer - IFEN"]
pub type IfenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FEMPT` reader - FEMPT"]
pub type FemptR = crate::BitReader;
#[doc = "Field `FEMPT` writer - FEMPT"]
pub type FemptW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - IRS"]
    #[inline(always)]
    pub fn irs(&self) -> IrsR {
        IrsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - ILS"]
    #[inline(always)]
    pub fn ils(&self) -> IlsR {
        IlsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - IFS"]
    #[inline(always)]
    pub fn ifs(&self) -> IfsR {
        IfsR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - IREN"]
    #[inline(always)]
    pub fn iren(&self) -> IrenR {
        IrenR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - ILEN"]
    #[inline(always)]
    pub fn ilen(&self) -> IlenR {
        IlenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - IFEN"]
    #[inline(always)]
    pub fn ifen(&self) -> IfenR {
        IfenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - FEMPT"]
    #[inline(always)]
    pub fn fempt(&self) -> FemptR {
        FemptR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - IRS"]
    #[inline(always)]
    #[must_use]
    pub fn irs(&mut self) -> IrsW<Sr4Spec> {
        IrsW::new(self, 0)
    }
    #[doc = "Bit 1 - ILS"]
    #[inline(always)]
    #[must_use]
    pub fn ils(&mut self) -> IlsW<Sr4Spec> {
        IlsW::new(self, 1)
    }
    #[doc = "Bit 2 - IFS"]
    #[inline(always)]
    #[must_use]
    pub fn ifs(&mut self) -> IfsW<Sr4Spec> {
        IfsW::new(self, 2)
    }
    #[doc = "Bit 3 - IREN"]
    #[inline(always)]
    #[must_use]
    pub fn iren(&mut self) -> IrenW<Sr4Spec> {
        IrenW::new(self, 3)
    }
    #[doc = "Bit 4 - ILEN"]
    #[inline(always)]
    #[must_use]
    pub fn ilen(&mut self) -> IlenW<Sr4Spec> {
        IlenW::new(self, 4)
    }
    #[doc = "Bit 5 - IFEN"]
    #[inline(always)]
    #[must_use]
    pub fn ifen(&mut self) -> IfenW<Sr4Spec> {
        IfenW::new(self, 5)
    }
    #[doc = "Bit 6 - FEMPT"]
    #[inline(always)]
    #[must_use]
    pub fn fempt(&mut self) -> FemptW<Sr4Spec> {
        FemptW::new(self, 6)
    }
}
#[doc = "FIFO status and interrupt register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sr4Spec;
impl crate::RegisterSpec for Sr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 164u64;
}
#[doc = "`read()` method returns [`sr4::R`](R) reader structure"]
impl crate::Readable for Sr4Spec {}
#[doc = "`write(|w| ..)` method takes [`sr4::W`](W) writer structure"]
impl crate::Writable for Sr4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR4 to value 0x40"]
impl crate::Resettable for Sr4Spec {
    const RESET_VALUE: u32 = 0x40;
}
