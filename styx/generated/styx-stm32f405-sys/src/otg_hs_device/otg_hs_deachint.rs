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
#[doc = "Register `OTG_HS_DEACHINT` reader"]
pub type R = crate::R<OtgHsDeachintSpec>;
#[doc = "Register `OTG_HS_DEACHINT` writer"]
pub type W = crate::W<OtgHsDeachintSpec>;
#[doc = "Field `IEP1INT` reader - IN endpoint 1interrupt bit"]
pub type Iep1intR = crate::BitReader;
#[doc = "Field `IEP1INT` writer - IN endpoint 1interrupt bit"]
pub type Iep1intW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OEP1INT` reader - OUT endpoint 1 interrupt bit"]
pub type Oep1intR = crate::BitReader;
#[doc = "Field `OEP1INT` writer - OUT endpoint 1 interrupt bit"]
pub type Oep1intW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - IN endpoint 1interrupt bit"]
    #[inline(always)]
    pub fn iep1int(&self) -> Iep1intR {
        Iep1intR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 17 - OUT endpoint 1 interrupt bit"]
    #[inline(always)]
    pub fn oep1int(&self) -> Oep1intR {
        Oep1intR::new(((self.bits >> 17) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - IN endpoint 1interrupt bit"]
    #[inline(always)]
    #[must_use]
    pub fn iep1int(&mut self) -> Iep1intW<OtgHsDeachintSpec> {
        Iep1intW::new(self, 1)
    }
    #[doc = "Bit 17 - OUT endpoint 1 interrupt bit"]
    #[inline(always)]
    #[must_use]
    pub fn oep1int(&mut self) -> Oep1intW<OtgHsDeachintSpec> {
        Oep1intW::new(self, 17)
    }
}
#[doc = "OTG_HS device each endpoint interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_deachint::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_deachint::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDeachintSpec;
impl crate::RegisterSpec for OtgHsDeachintSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`otg_hs_deachint::R`](R) reader structure"]
impl crate::Readable for OtgHsDeachintSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_deachint::W`](W) writer structure"]
impl crate::Writable for OtgHsDeachintSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DEACHINT to value 0"]
impl crate::Resettable for OtgHsDeachintSpec {
    const RESET_VALUE: u32 = 0;
}
