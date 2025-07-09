// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SAI_BCLRFR` reader"]
pub type R = crate::R<SaiBclrfrSpec>;
#[doc = "Register `SAI_BCLRFR` writer"]
pub type W = crate::W<SaiBclrfrSpec>;
#[doc = "Field `COVRUDR` reader - Clear overrun / underrun"]
pub type CovrudrR = crate::BitReader;
#[doc = "Field `COVRUDR` writer - Clear overrun / underrun"]
pub type CovrudrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMUTEDET` reader - Mute detection flag"]
pub type CmutedetR = crate::BitReader;
#[doc = "Field `CMUTEDET` writer - Mute detection flag"]
pub type CmutedetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CWCKCFG` reader - Clear wrong clock configuration flag"]
pub type CwckcfgR = crate::BitReader;
#[doc = "Field `CWCKCFG` writer - Clear wrong clock configuration flag"]
pub type CwckcfgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CCNRDY` reader - Clear codec not ready flag"]
pub type CcnrdyR = crate::BitReader;
#[doc = "Field `CCNRDY` writer - Clear codec not ready flag"]
pub type CcnrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAFSDET` reader - Clear anticipated frame synchronization detection flag"]
pub type CafsdetR = crate::BitReader;
#[doc = "Field `CAFSDET` writer - Clear anticipated frame synchronization detection flag"]
pub type CafsdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CLFSDET` reader - Clear late frame synchronization detection flag"]
pub type ClfsdetR = crate::BitReader;
#[doc = "Field `CLFSDET` writer - Clear late frame synchronization detection flag"]
pub type ClfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clear overrun / underrun"]
    #[inline(always)]
    pub fn covrudr(&self) -> CovrudrR {
        CovrudrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mute detection flag"]
    #[inline(always)]
    pub fn cmutedet(&self) -> CmutedetR {
        CmutedetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Clear wrong clock configuration flag"]
    #[inline(always)]
    pub fn cwckcfg(&self) -> CwckcfgR {
        CwckcfgR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - Clear codec not ready flag"]
    #[inline(always)]
    pub fn ccnrdy(&self) -> CcnrdyR {
        CcnrdyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Clear anticipated frame synchronization detection flag"]
    #[inline(always)]
    pub fn cafsdet(&self) -> CafsdetR {
        CafsdetR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Clear late frame synchronization detection flag"]
    #[inline(always)]
    pub fn clfsdet(&self) -> ClfsdetR {
        ClfsdetR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clear overrun / underrun"]
    #[inline(always)]
    #[must_use]
    pub fn covrudr(&mut self) -> CovrudrW<SaiBclrfrSpec> {
        CovrudrW::new(self, 0)
    }
    #[doc = "Bit 1 - Mute detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn cmutedet(&mut self) -> CmutedetW<SaiBclrfrSpec> {
        CmutedetW::new(self, 1)
    }
    #[doc = "Bit 2 - Clear wrong clock configuration flag"]
    #[inline(always)]
    #[must_use]
    pub fn cwckcfg(&mut self) -> CwckcfgW<SaiBclrfrSpec> {
        CwckcfgW::new(self, 2)
    }
    #[doc = "Bit 4 - Clear codec not ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn ccnrdy(&mut self) -> CcnrdyW<SaiBclrfrSpec> {
        CcnrdyW::new(self, 4)
    }
    #[doc = "Bit 5 - Clear anticipated frame synchronization detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn cafsdet(&mut self) -> CafsdetW<SaiBclrfrSpec> {
        CafsdetW::new(self, 5)
    }
    #[doc = "Bit 6 - Clear late frame synchronization detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn clfsdet(&mut self) -> ClfsdetW<SaiBclrfrSpec> {
        ClfsdetW::new(self, 6)
    }
}
#[doc = "SAI BClear flag register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bclrfr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bclrfr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiBclrfrSpec;
impl crate::RegisterSpec for SaiBclrfrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`sai_bclrfr::R`](R) reader structure"]
impl crate::Readable for SaiBclrfrSpec {}
#[doc = "`write(|w| ..)` method takes [`sai_bclrfr::W`](W) writer structure"]
impl crate::Writable for SaiBclrfrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SAI_BCLRFR to value 0"]
impl crate::Resettable for SaiBclrfrSpec {
    const RESET_VALUE: u32 = 0;
}
