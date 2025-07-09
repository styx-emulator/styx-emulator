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
#[doc = "Register `slavegrp_dap_fn_mod2` reader"]
pub type R = crate::R<SlavegrpDapFnMod2Spec>;
#[doc = "Register `slavegrp_dap_fn_mod2` writer"]
pub type W = crate::W<SlavegrpDapFnMod2Spec>;
#[doc = "Controls bypass merge of upsizing/downsizing.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BypassMerge {
    #[doc = "0: `0`"]
    Alter = 0,
    #[doc = "1: `1`"]
    Noalter = 1,
}
impl From<BypassMerge> for bool {
    #[inline(always)]
    fn from(variant: BypassMerge) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bypass_merge` reader - Controls bypass merge of upsizing/downsizing."]
pub type BypassMergeR = crate::BitReader<BypassMerge>;
impl BypassMergeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> BypassMerge {
        match self.bits {
            false => BypassMerge::Alter,
            true => BypassMerge::Noalter,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_alter(&self) -> bool {
        *self == BypassMerge::Alter
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_noalter(&self) -> bool {
        *self == BypassMerge::Noalter
    }
}
#[doc = "Field `bypass_merge` writer - Controls bypass merge of upsizing/downsizing."]
pub type BypassMergeW<'a, REG> = crate::BitWriter<'a, REG, BypassMerge>;
impl<'a, REG> BypassMergeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn alter(self) -> &'a mut crate::W<REG> {
        self.variant(BypassMerge::Alter)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn noalter(self) -> &'a mut crate::W<REG> {
        self.variant(BypassMerge::Noalter)
    }
}
impl R {
    #[doc = "Bit 0 - Controls bypass merge of upsizing/downsizing."]
    #[inline(always)]
    pub fn bypass_merge(&self) -> BypassMergeR {
        BypassMergeR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls bypass merge of upsizing/downsizing."]
    #[inline(always)]
    #[must_use]
    pub fn bypass_merge(&mut self) -> BypassMergeW<SlavegrpDapFnMod2Spec> {
        BypassMergeW::new(self, 0)
    }
}
#[doc = "Controls bypass merge of upsizing/downsizing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_fn_mod2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_fn_mod2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SlavegrpDapFnMod2Spec;
impl crate::RegisterSpec for SlavegrpDapFnMod2Spec {
    type Ux = u32;
    const OFFSET: u64 = 270372u64;
}
#[doc = "`read()` method returns [`slavegrp_dap_fn_mod2::R`](R) reader structure"]
impl crate::Readable for SlavegrpDapFnMod2Spec {}
#[doc = "`write(|w| ..)` method takes [`slavegrp_dap_fn_mod2::W`](W) writer structure"]
impl crate::Writable for SlavegrpDapFnMod2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets slavegrp_dap_fn_mod2 to value 0"]
impl crate::Resettable for SlavegrpDapFnMod2Spec {
    const RESET_VALUE: u32 = 0;
}
