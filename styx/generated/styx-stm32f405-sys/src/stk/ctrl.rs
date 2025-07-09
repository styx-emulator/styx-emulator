// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CTRL` reader"]
pub type R = crate::R<CtrlSpec>;
#[doc = "Register `CTRL` writer"]
pub type W = crate::W<CtrlSpec>;
#[doc = "Field `ENABLE` reader - Counter enable"]
pub type EnableR = crate::BitReader;
#[doc = "Field `ENABLE` writer - Counter enable"]
pub type EnableW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TICKINT` reader - SysTick exception request enable"]
pub type TickintR = crate::BitReader;
#[doc = "Field `TICKINT` writer - SysTick exception request enable"]
pub type TickintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CLKSOURCE` reader - Clock source selection"]
pub type ClksourceR = crate::BitReader;
#[doc = "Field `CLKSOURCE` writer - Clock source selection"]
pub type ClksourceW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COUNTFLAG` reader - COUNTFLAG"]
pub type CountflagR = crate::BitReader;
#[doc = "Field `COUNTFLAG` writer - COUNTFLAG"]
pub type CountflagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Counter enable"]
    #[inline(always)]
    pub fn enable(&self) -> EnableR {
        EnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - SysTick exception request enable"]
    #[inline(always)]
    pub fn tickint(&self) -> TickintR {
        TickintR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Clock source selection"]
    #[inline(always)]
    pub fn clksource(&self) -> ClksourceR {
        ClksourceR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 16 - COUNTFLAG"]
    #[inline(always)]
    pub fn countflag(&self) -> CountflagR {
        CountflagR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Counter enable"]
    #[inline(always)]
    #[must_use]
    pub fn enable(&mut self) -> EnableW<CtrlSpec> {
        EnableW::new(self, 0)
    }
    #[doc = "Bit 1 - SysTick exception request enable"]
    #[inline(always)]
    #[must_use]
    pub fn tickint(&mut self) -> TickintW<CtrlSpec> {
        TickintW::new(self, 1)
    }
    #[doc = "Bit 2 - Clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn clksource(&mut self) -> ClksourceW<CtrlSpec> {
        ClksourceW::new(self, 2)
    }
    #[doc = "Bit 16 - COUNTFLAG"]
    #[inline(always)]
    #[must_use]
    pub fn countflag(&mut self) -> CountflagW<CtrlSpec> {
        CountflagW::new(self, 16)
    }
}
#[doc = "SysTick control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlSpec;
impl crate::RegisterSpec for CtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`ctrl::R`](R) reader structure"]
impl crate::Readable for CtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrl::W`](W) writer structure"]
impl crate::Writable for CtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CTRL to value 0"]
impl crate::Resettable for CtrlSpec {
    const RESET_VALUE: u32 = 0;
}
