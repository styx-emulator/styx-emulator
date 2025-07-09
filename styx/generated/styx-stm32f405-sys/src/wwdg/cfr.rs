// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CFR` reader"]
pub type R = crate::R<CfrSpec>;
#[doc = "Register `CFR` writer"]
pub type W = crate::W<CfrSpec>;
#[doc = "Field `W` reader - 7-bit window value"]
pub type WR = crate::FieldReader;
#[doc = "Field `W` writer - 7-bit window value"]
pub type WW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `WDGTB0` reader - Timer base"]
pub type Wdgtb0R = crate::BitReader;
#[doc = "Field `WDGTB0` writer - Timer base"]
pub type Wdgtb0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WDGTB1` reader - Timer base"]
pub type Wdgtb1R = crate::BitReader;
#[doc = "Field `WDGTB1` writer - Timer base"]
pub type Wdgtb1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWI` reader - Early wakeup interrupt"]
pub type EwiR = crate::BitReader;
#[doc = "Field `EWI` writer - Early wakeup interrupt"]
pub type EwiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:6 - 7-bit window value"]
    #[inline(always)]
    pub fn w(&self) -> WR {
        WR::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bit 7 - Timer base"]
    #[inline(always)]
    pub fn wdgtb0(&self) -> Wdgtb0R {
        Wdgtb0R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Timer base"]
    #[inline(always)]
    pub fn wdgtb1(&self) -> Wdgtb1R {
        Wdgtb1R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Early wakeup interrupt"]
    #[inline(always)]
    pub fn ewi(&self) -> EwiR {
        EwiR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:6 - 7-bit window value"]
    #[inline(always)]
    #[must_use]
    pub fn w(&mut self) -> WW<CfrSpec> {
        WW::new(self, 0)
    }
    #[doc = "Bit 7 - Timer base"]
    #[inline(always)]
    #[must_use]
    pub fn wdgtb0(&mut self) -> Wdgtb0W<CfrSpec> {
        Wdgtb0W::new(self, 7)
    }
    #[doc = "Bit 8 - Timer base"]
    #[inline(always)]
    #[must_use]
    pub fn wdgtb1(&mut self) -> Wdgtb1W<CfrSpec> {
        Wdgtb1W::new(self, 8)
    }
    #[doc = "Bit 9 - Early wakeup interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn ewi(&mut self) -> EwiW<CfrSpec> {
        EwiW::new(self, 9)
    }
}
#[doc = "Configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CfrSpec;
impl crate::RegisterSpec for CfrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`cfr::R`](R) reader structure"]
impl crate::Readable for CfrSpec {}
#[doc = "`write(|w| ..)` method takes [`cfr::W`](W) writer structure"]
impl crate::Writable for CfrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CFR to value 0x7f"]
impl crate::Resettable for CfrSpec {
    const RESET_VALUE: u32 = 0x7f;
}
