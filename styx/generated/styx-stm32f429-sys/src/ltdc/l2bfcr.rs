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
#[doc = "Register `L2BFCR` reader"]
pub type R = crate::R<L2bfcrSpec>;
#[doc = "Register `L2BFCR` writer"]
pub type W = crate::W<L2bfcrSpec>;
#[doc = "Field `BF2` reader - Blending Factor 2"]
pub type Bf2R = crate::FieldReader;
#[doc = "Field `BF2` writer - Blending Factor 2"]
pub type Bf2W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `BF1` reader - Blending Factor 1"]
pub type Bf1R = crate::FieldReader;
#[doc = "Field `BF1` writer - Blending Factor 1"]
pub type Bf1W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:2 - Blending Factor 2"]
    #[inline(always)]
    pub fn bf2(&self) -> Bf2R {
        Bf2R::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 8:10 - Blending Factor 1"]
    #[inline(always)]
    pub fn bf1(&self) -> Bf1R {
        Bf1R::new(((self.bits >> 8) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - Blending Factor 2"]
    #[inline(always)]
    #[must_use]
    pub fn bf2(&mut self) -> Bf2W<L2bfcrSpec> {
        Bf2W::new(self, 0)
    }
    #[doc = "Bits 8:10 - Blending Factor 1"]
    #[inline(always)]
    #[must_use]
    pub fn bf1(&mut self) -> Bf1W<L2bfcrSpec> {
        Bf1W::new(self, 8)
    }
}
#[doc = "Layerx Blending Factors Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2bfcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2bfcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L2bfcrSpec;
impl crate::RegisterSpec for L2bfcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`l2bfcr::R`](R) reader structure"]
impl crate::Readable for L2bfcrSpec {}
#[doc = "`write(|w| ..)` method takes [`l2bfcr::W`](W) writer structure"]
impl crate::Writable for L2bfcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L2BFCR to value 0x0607"]
impl crate::Resettable for L2bfcrSpec {
    const RESET_VALUE: u32 = 0x0607;
}
