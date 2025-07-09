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
#[doc = "Register `mastergrp_l4main_fn_mod_bm_iss` reader"]
pub type R = crate::R<MastergrpL4mainFnModBmIssSpec>;
#[doc = "Register `mastergrp_l4main_fn_mod_bm_iss` writer"]
pub type W = crate::W<MastergrpL4mainFnModBmIssSpec>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rd {
    #[doc = "0: `0`"]
    Multiple = 0,
    #[doc = "1: `1`"]
    Single = 1,
}
impl From<Rd> for bool {
    #[inline(always)]
    fn from(variant: Rd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rd` reader - "]
pub type RdR = crate::BitReader<Rd>;
impl RdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rd {
        match self.bits {
            false => Rd::Multiple,
            true => Rd::Single,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_multiple(&self) -> bool {
        *self == Rd::Multiple
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Rd::Single
    }
}
#[doc = "Field `rd` writer - "]
pub type RdW<'a, REG> = crate::BitWriter<'a, REG, Rd>;
impl<'a, REG> RdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn multiple(self) -> &'a mut crate::W<REG> {
        self.variant(Rd::Multiple)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Rd::Single)
    }
}
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wr {
    #[doc = "0: `0`"]
    Multiple = 0,
    #[doc = "1: `1`"]
    Single = 1,
}
impl From<Wr> for bool {
    #[inline(always)]
    fn from(variant: Wr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wr` reader - "]
pub type WrR = crate::BitReader<Wr>;
impl WrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wr {
        match self.bits {
            false => Wr::Multiple,
            true => Wr::Single,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_multiple(&self) -> bool {
        *self == Wr::Multiple
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Wr::Single
    }
}
#[doc = "Field `wr` writer - "]
pub type WrW<'a, REG> = crate::BitWriter<'a, REG, Wr>;
impl<'a, REG> WrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn multiple(self) -> &'a mut crate::W<REG> {
        self.variant(Wr::Multiple)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Wr::Single)
    }
}
impl R {
    #[doc = "Bit 0"]
    #[inline(always)]
    pub fn rd(&self) -> RdR {
        RdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    pub fn wr(&self) -> WrR {
        WrR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0"]
    #[inline(always)]
    #[must_use]
    pub fn rd(&mut self) -> RdW<MastergrpL4mainFnModBmIssSpec> {
        RdW::new(self, 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn wr(&mut self) -> WrW<MastergrpL4mainFnModBmIssSpec> {
        WrW::new(self, 1)
    }
}
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_l4main_fn_mod_bm_iss::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_l4main_fn_mod_bm_iss::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MastergrpL4mainFnModBmIssSpec;
impl crate::RegisterSpec for MastergrpL4mainFnModBmIssSpec {
    type Ux = u32;
    const OFFSET: u64 = 8200u64;
}
#[doc = "`read()` method returns [`mastergrp_l4main_fn_mod_bm_iss::R`](R) reader structure"]
impl crate::Readable for MastergrpL4mainFnModBmIssSpec {}
#[doc = "`write(|w| ..)` method takes [`mastergrp_l4main_fn_mod_bm_iss::W`](W) writer structure"]
impl crate::Writable for MastergrpL4mainFnModBmIssSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mastergrp_l4main_fn_mod_bm_iss to value 0"]
impl crate::Resettable for MastergrpL4mainFnModBmIssSpec {
    const RESET_VALUE: u32 = 0;
}
