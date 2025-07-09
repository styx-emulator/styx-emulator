// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCR` reader"]
pub type R = crate::R<CcrSpec>;
#[doc = "Register `CCR` writer"]
pub type W = crate::W<CcrSpec>;
#[doc = "Field `NONBASETHRDENA` reader - Configures how the processor enters Thread mode"]
pub type NonbasethrdenaR = crate::BitReader;
#[doc = "Field `NONBASETHRDENA` writer - Configures how the processor enters Thread mode"]
pub type NonbasethrdenaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USERSETMPEND` reader - USERSETMPEND"]
pub type UsersetmpendR = crate::BitReader;
#[doc = "Field `USERSETMPEND` writer - USERSETMPEND"]
pub type UsersetmpendW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UNALIGN__TRP` reader - UNALIGN_ TRP"]
pub type Unalign_TrpR = crate::BitReader;
#[doc = "Field `UNALIGN__TRP` writer - UNALIGN_ TRP"]
pub type Unalign_TrpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DIV_0_TRP` reader - DIV_0_TRP"]
pub type Div0TrpR = crate::BitReader;
#[doc = "Field `DIV_0_TRP` writer - DIV_0_TRP"]
pub type Div0TrpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BFHFNMIGN` reader - BFHFNMIGN"]
pub type BfhfnmignR = crate::BitReader;
#[doc = "Field `BFHFNMIGN` writer - BFHFNMIGN"]
pub type BfhfnmignW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STKALIGN` reader - STKALIGN"]
pub type StkalignR = crate::BitReader;
#[doc = "Field `STKALIGN` writer - STKALIGN"]
pub type StkalignW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Configures how the processor enters Thread mode"]
    #[inline(always)]
    pub fn nonbasethrdena(&self) -> NonbasethrdenaR {
        NonbasethrdenaR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - USERSETMPEND"]
    #[inline(always)]
    pub fn usersetmpend(&self) -> UsersetmpendR {
        UsersetmpendR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - UNALIGN_ TRP"]
    #[inline(always)]
    pub fn unalign__trp(&self) -> Unalign_TrpR {
        Unalign_TrpR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - DIV_0_TRP"]
    #[inline(always)]
    pub fn div_0_trp(&self) -> Div0TrpR {
        Div0TrpR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 8 - BFHFNMIGN"]
    #[inline(always)]
    pub fn bfhfnmign(&self) -> BfhfnmignR {
        BfhfnmignR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - STKALIGN"]
    #[inline(always)]
    pub fn stkalign(&self) -> StkalignR {
        StkalignR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Configures how the processor enters Thread mode"]
    #[inline(always)]
    #[must_use]
    pub fn nonbasethrdena(&mut self) -> NonbasethrdenaW<CcrSpec> {
        NonbasethrdenaW::new(self, 0)
    }
    #[doc = "Bit 1 - USERSETMPEND"]
    #[inline(always)]
    #[must_use]
    pub fn usersetmpend(&mut self) -> UsersetmpendW<CcrSpec> {
        UsersetmpendW::new(self, 1)
    }
    #[doc = "Bit 3 - UNALIGN_ TRP"]
    #[inline(always)]
    #[must_use]
    pub fn unalign__trp(&mut self) -> Unalign_TrpW<CcrSpec> {
        Unalign_TrpW::new(self, 3)
    }
    #[doc = "Bit 4 - DIV_0_TRP"]
    #[inline(always)]
    #[must_use]
    pub fn div_0_trp(&mut self) -> Div0TrpW<CcrSpec> {
        Div0TrpW::new(self, 4)
    }
    #[doc = "Bit 8 - BFHFNMIGN"]
    #[inline(always)]
    #[must_use]
    pub fn bfhfnmign(&mut self) -> BfhfnmignW<CcrSpec> {
        BfhfnmignW::new(self, 8)
    }
    #[doc = "Bit 9 - STKALIGN"]
    #[inline(always)]
    #[must_use]
    pub fn stkalign(&mut self) -> StkalignW<CcrSpec> {
        StkalignW::new(self, 9)
    }
}
#[doc = "Configuration and control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CcrSpec;
impl crate::RegisterSpec for CcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`ccr::R`](R) reader structure"]
impl crate::Readable for CcrSpec {}
#[doc = "`write(|w| ..)` method takes [`ccr::W`](W) writer structure"]
impl crate::Writable for CcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCR to value 0"]
impl crate::Resettable for CcrSpec {
    const RESET_VALUE: u32 = 0;
}
