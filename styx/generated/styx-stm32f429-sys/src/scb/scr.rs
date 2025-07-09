// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SCR` reader"]
pub type R = crate::R<ScrSpec>;
#[doc = "Register `SCR` writer"]
pub type W = crate::W<ScrSpec>;
#[doc = "Field `SLEEPONEXIT` reader - SLEEPONEXIT"]
pub type SleeponexitR = crate::BitReader;
#[doc = "Field `SLEEPONEXIT` writer - SLEEPONEXIT"]
pub type SleeponexitW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SLEEPDEEP` reader - SLEEPDEEP"]
pub type SleepdeepR = crate::BitReader;
#[doc = "Field `SLEEPDEEP` writer - SLEEPDEEP"]
pub type SleepdeepW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SEVEONPEND` reader - Send Event on Pending bit"]
pub type SeveonpendR = crate::BitReader;
#[doc = "Field `SEVEONPEND` writer - Send Event on Pending bit"]
pub type SeveonpendW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - SLEEPONEXIT"]
    #[inline(always)]
    pub fn sleeponexit(&self) -> SleeponexitR {
        SleeponexitR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - SLEEPDEEP"]
    #[inline(always)]
    pub fn sleepdeep(&self) -> SleepdeepR {
        SleepdeepR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - Send Event on Pending bit"]
    #[inline(always)]
    pub fn seveonpend(&self) -> SeveonpendR {
        SeveonpendR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - SLEEPONEXIT"]
    #[inline(always)]
    #[must_use]
    pub fn sleeponexit(&mut self) -> SleeponexitW<ScrSpec> {
        SleeponexitW::new(self, 1)
    }
    #[doc = "Bit 2 - SLEEPDEEP"]
    #[inline(always)]
    #[must_use]
    pub fn sleepdeep(&mut self) -> SleepdeepW<ScrSpec> {
        SleepdeepW::new(self, 2)
    }
    #[doc = "Bit 4 - Send Event on Pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn seveonpend(&mut self) -> SeveonpendW<ScrSpec> {
        SeveonpendW::new(self, 4)
    }
}
#[doc = "System control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`scr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`scr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ScrSpec;
impl crate::RegisterSpec for ScrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`scr::R`](R) reader structure"]
impl crate::Readable for ScrSpec {}
#[doc = "`write(|w| ..)` method takes [`scr::W`](W) writer structure"]
impl crate::Writable for ScrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SCR to value 0"]
impl crate::Resettable for ScrSpec {
    const RESET_VALUE: u32 = 0;
}
