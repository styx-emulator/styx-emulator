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
#[doc = "Register `IPR9` reader"]
pub type R = crate::R<Ipr9Spec>;
#[doc = "Register `IPR9` writer"]
pub type W = crate::W<Ipr9Spec>;
#[doc = "Field `IPR_N0` reader - IPR_N0"]
pub type IprN0R = crate::FieldReader;
#[doc = "Field `IPR_N0` writer - IPR_N0"]
pub type IprN0W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IPR_N1` reader - IPR_N1"]
pub type IprN1R = crate::FieldReader;
#[doc = "Field `IPR_N1` writer - IPR_N1"]
pub type IprN1W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IPR_N2` reader - IPR_N2"]
pub type IprN2R = crate::FieldReader;
#[doc = "Field `IPR_N2` writer - IPR_N2"]
pub type IprN2W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IPR_N3` reader - IPR_N3"]
pub type IprN3R = crate::FieldReader;
#[doc = "Field `IPR_N3` writer - IPR_N3"]
pub type IprN3W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - IPR_N0"]
    #[inline(always)]
    pub fn ipr_n0(&self) -> IprN0R {
        IprN0R::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - IPR_N1"]
    #[inline(always)]
    pub fn ipr_n1(&self) -> IprN1R {
        IprN1R::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - IPR_N2"]
    #[inline(always)]
    pub fn ipr_n2(&self) -> IprN2R {
        IprN2R::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - IPR_N3"]
    #[inline(always)]
    pub fn ipr_n3(&self) -> IprN3R {
        IprN3R::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - IPR_N0"]
    #[inline(always)]
    #[must_use]
    pub fn ipr_n0(&mut self) -> IprN0W<Ipr9Spec> {
        IprN0W::new(self, 0)
    }
    #[doc = "Bits 8:15 - IPR_N1"]
    #[inline(always)]
    #[must_use]
    pub fn ipr_n1(&mut self) -> IprN1W<Ipr9Spec> {
        IprN1W::new(self, 8)
    }
    #[doc = "Bits 16:23 - IPR_N2"]
    #[inline(always)]
    #[must_use]
    pub fn ipr_n2(&mut self) -> IprN2W<Ipr9Spec> {
        IprN2W::new(self, 16)
    }
    #[doc = "Bits 24:31 - IPR_N3"]
    #[inline(always)]
    #[must_use]
    pub fn ipr_n3(&mut self) -> IprN3W<Ipr9Spec> {
        IprN3W::new(self, 24)
    }
}
#[doc = "Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr9::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr9::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ipr9Spec;
impl crate::RegisterSpec for Ipr9Spec {
    type Ux = u32;
    const OFFSET: u64 = 804u64;
}
#[doc = "`read()` method returns [`ipr9::R`](R) reader structure"]
impl crate::Readable for Ipr9Spec {}
#[doc = "`write(|w| ..)` method takes [`ipr9::W`](W) writer structure"]
impl crate::Writable for Ipr9Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets IPR9 to value 0"]
impl crate::Resettable for Ipr9Spec {
    const RESET_VALUE: u32 = 0;
}
