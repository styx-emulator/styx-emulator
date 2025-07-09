// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ACTRL` reader"]
pub type R = crate::R<ActrlSpec>;
#[doc = "Register `ACTRL` writer"]
pub type W = crate::W<ActrlSpec>;
#[doc = "Field `DISMCYCINT` reader - DISMCYCINT"]
pub type DismcycintR = crate::BitReader;
#[doc = "Field `DISMCYCINT` writer - DISMCYCINT"]
pub type DismcycintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISDEFWBUF` reader - DISDEFWBUF"]
pub type DisdefwbufR = crate::BitReader;
#[doc = "Field `DISDEFWBUF` writer - DISDEFWBUF"]
pub type DisdefwbufW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISFOLD` reader - DISFOLD"]
pub type DisfoldR = crate::BitReader;
#[doc = "Field `DISFOLD` writer - DISFOLD"]
pub type DisfoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISFPCA` reader - DISFPCA"]
pub type DisfpcaR = crate::BitReader;
#[doc = "Field `DISFPCA` writer - DISFPCA"]
pub type DisfpcaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISOOFP` reader - DISOOFP"]
pub type DisoofpR = crate::BitReader;
#[doc = "Field `DISOOFP` writer - DISOOFP"]
pub type DisoofpW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - DISMCYCINT"]
    #[inline(always)]
    pub fn dismcycint(&self) -> DismcycintR {
        DismcycintR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - DISDEFWBUF"]
    #[inline(always)]
    pub fn disdefwbuf(&self) -> DisdefwbufR {
        DisdefwbufR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - DISFOLD"]
    #[inline(always)]
    pub fn disfold(&self) -> DisfoldR {
        DisfoldR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 8 - DISFPCA"]
    #[inline(always)]
    pub fn disfpca(&self) -> DisfpcaR {
        DisfpcaR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - DISOOFP"]
    #[inline(always)]
    pub fn disoofp(&self) -> DisoofpR {
        DisoofpR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - DISMCYCINT"]
    #[inline(always)]
    #[must_use]
    pub fn dismcycint(&mut self) -> DismcycintW<ActrlSpec> {
        DismcycintW::new(self, 0)
    }
    #[doc = "Bit 1 - DISDEFWBUF"]
    #[inline(always)]
    #[must_use]
    pub fn disdefwbuf(&mut self) -> DisdefwbufW<ActrlSpec> {
        DisdefwbufW::new(self, 1)
    }
    #[doc = "Bit 2 - DISFOLD"]
    #[inline(always)]
    #[must_use]
    pub fn disfold(&mut self) -> DisfoldW<ActrlSpec> {
        DisfoldW::new(self, 2)
    }
    #[doc = "Bit 8 - DISFPCA"]
    #[inline(always)]
    #[must_use]
    pub fn disfpca(&mut self) -> DisfpcaW<ActrlSpec> {
        DisfpcaW::new(self, 8)
    }
    #[doc = "Bit 9 - DISOOFP"]
    #[inline(always)]
    #[must_use]
    pub fn disoofp(&mut self) -> DisoofpW<ActrlSpec> {
        DisoofpW::new(self, 9)
    }
}
#[doc = "Auxiliary control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`actrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`actrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ActrlSpec;
impl crate::RegisterSpec for ActrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`actrl::R`](R) reader structure"]
impl crate::Readable for ActrlSpec {}
#[doc = "`write(|w| ..)` method takes [`actrl::W`](W) writer structure"]
impl crate::Writable for ActrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ACTRL to value 0"]
impl crate::Resettable for ActrlSpec {
    const RESET_VALUE: u32 = 0;
}
