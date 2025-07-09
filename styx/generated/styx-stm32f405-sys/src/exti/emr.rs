// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `EMR` reader"]
pub type R = crate::R<EmrSpec>;
#[doc = "Register `EMR` writer"]
pub type W = crate::W<EmrSpec>;
#[doc = "Field `MR0` reader - Event Mask on line 0"]
pub type Mr0R = crate::BitReader;
#[doc = "Field `MR0` writer - Event Mask on line 0"]
pub type Mr0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR1` reader - Event Mask on line 1"]
pub type Mr1R = crate::BitReader;
#[doc = "Field `MR1` writer - Event Mask on line 1"]
pub type Mr1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR2` reader - Event Mask on line 2"]
pub type Mr2R = crate::BitReader;
#[doc = "Field `MR2` writer - Event Mask on line 2"]
pub type Mr2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR3` reader - Event Mask on line 3"]
pub type Mr3R = crate::BitReader;
#[doc = "Field `MR3` writer - Event Mask on line 3"]
pub type Mr3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR4` reader - Event Mask on line 4"]
pub type Mr4R = crate::BitReader;
#[doc = "Field `MR4` writer - Event Mask on line 4"]
pub type Mr4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR5` reader - Event Mask on line 5"]
pub type Mr5R = crate::BitReader;
#[doc = "Field `MR5` writer - Event Mask on line 5"]
pub type Mr5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR6` reader - Event Mask on line 6"]
pub type Mr6R = crate::BitReader;
#[doc = "Field `MR6` writer - Event Mask on line 6"]
pub type Mr6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR7` reader - Event Mask on line 7"]
pub type Mr7R = crate::BitReader;
#[doc = "Field `MR7` writer - Event Mask on line 7"]
pub type Mr7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR8` reader - Event Mask on line 8"]
pub type Mr8R = crate::BitReader;
#[doc = "Field `MR8` writer - Event Mask on line 8"]
pub type Mr8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR9` reader - Event Mask on line 9"]
pub type Mr9R = crate::BitReader;
#[doc = "Field `MR9` writer - Event Mask on line 9"]
pub type Mr9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR10` reader - Event Mask on line 10"]
pub type Mr10R = crate::BitReader;
#[doc = "Field `MR10` writer - Event Mask on line 10"]
pub type Mr10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR11` reader - Event Mask on line 11"]
pub type Mr11R = crate::BitReader;
#[doc = "Field `MR11` writer - Event Mask on line 11"]
pub type Mr11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR12` reader - Event Mask on line 12"]
pub type Mr12R = crate::BitReader;
#[doc = "Field `MR12` writer - Event Mask on line 12"]
pub type Mr12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR13` reader - Event Mask on line 13"]
pub type Mr13R = crate::BitReader;
#[doc = "Field `MR13` writer - Event Mask on line 13"]
pub type Mr13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR14` reader - Event Mask on line 14"]
pub type Mr14R = crate::BitReader;
#[doc = "Field `MR14` writer - Event Mask on line 14"]
pub type Mr14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR15` reader - Event Mask on line 15"]
pub type Mr15R = crate::BitReader;
#[doc = "Field `MR15` writer - Event Mask on line 15"]
pub type Mr15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR16` reader - Event Mask on line 16"]
pub type Mr16R = crate::BitReader;
#[doc = "Field `MR16` writer - Event Mask on line 16"]
pub type Mr16W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR17` reader - Event Mask on line 17"]
pub type Mr17R = crate::BitReader;
#[doc = "Field `MR17` writer - Event Mask on line 17"]
pub type Mr17W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR18` reader - Event Mask on line 18"]
pub type Mr18R = crate::BitReader;
#[doc = "Field `MR18` writer - Event Mask on line 18"]
pub type Mr18W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR19` reader - Event Mask on line 19"]
pub type Mr19R = crate::BitReader;
#[doc = "Field `MR19` writer - Event Mask on line 19"]
pub type Mr19W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR20` reader - Event Mask on line 20"]
pub type Mr20R = crate::BitReader;
#[doc = "Field `MR20` writer - Event Mask on line 20"]
pub type Mr20W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR21` reader - Event Mask on line 21"]
pub type Mr21R = crate::BitReader;
#[doc = "Field `MR21` writer - Event Mask on line 21"]
pub type Mr21W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MR22` reader - Event Mask on line 22"]
pub type Mr22R = crate::BitReader;
#[doc = "Field `MR22` writer - Event Mask on line 22"]
pub type Mr22W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Event Mask on line 0"]
    #[inline(always)]
    pub fn mr0(&self) -> Mr0R {
        Mr0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Event Mask on line 1"]
    #[inline(always)]
    pub fn mr1(&self) -> Mr1R {
        Mr1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Event Mask on line 2"]
    #[inline(always)]
    pub fn mr2(&self) -> Mr2R {
        Mr2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Event Mask on line 3"]
    #[inline(always)]
    pub fn mr3(&self) -> Mr3R {
        Mr3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Event Mask on line 4"]
    #[inline(always)]
    pub fn mr4(&self) -> Mr4R {
        Mr4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Event Mask on line 5"]
    #[inline(always)]
    pub fn mr5(&self) -> Mr5R {
        Mr5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Event Mask on line 6"]
    #[inline(always)]
    pub fn mr6(&self) -> Mr6R {
        Mr6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Event Mask on line 7"]
    #[inline(always)]
    pub fn mr7(&self) -> Mr7R {
        Mr7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Event Mask on line 8"]
    #[inline(always)]
    pub fn mr8(&self) -> Mr8R {
        Mr8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Event Mask on line 9"]
    #[inline(always)]
    pub fn mr9(&self) -> Mr9R {
        Mr9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Event Mask on line 10"]
    #[inline(always)]
    pub fn mr10(&self) -> Mr10R {
        Mr10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Event Mask on line 11"]
    #[inline(always)]
    pub fn mr11(&self) -> Mr11R {
        Mr11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Event Mask on line 12"]
    #[inline(always)]
    pub fn mr12(&self) -> Mr12R {
        Mr12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Event Mask on line 13"]
    #[inline(always)]
    pub fn mr13(&self) -> Mr13R {
        Mr13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Event Mask on line 14"]
    #[inline(always)]
    pub fn mr14(&self) -> Mr14R {
        Mr14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Event Mask on line 15"]
    #[inline(always)]
    pub fn mr15(&self) -> Mr15R {
        Mr15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Event Mask on line 16"]
    #[inline(always)]
    pub fn mr16(&self) -> Mr16R {
        Mr16R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Event Mask on line 17"]
    #[inline(always)]
    pub fn mr17(&self) -> Mr17R {
        Mr17R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Event Mask on line 18"]
    #[inline(always)]
    pub fn mr18(&self) -> Mr18R {
        Mr18R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Event Mask on line 19"]
    #[inline(always)]
    pub fn mr19(&self) -> Mr19R {
        Mr19R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Event Mask on line 20"]
    #[inline(always)]
    pub fn mr20(&self) -> Mr20R {
        Mr20R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Event Mask on line 21"]
    #[inline(always)]
    pub fn mr21(&self) -> Mr21R {
        Mr21R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Event Mask on line 22"]
    #[inline(always)]
    pub fn mr22(&self) -> Mr22R {
        Mr22R::new(((self.bits >> 22) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Event Mask on line 0"]
    #[inline(always)]
    #[must_use]
    pub fn mr0(&mut self) -> Mr0W<EmrSpec> {
        Mr0W::new(self, 0)
    }
    #[doc = "Bit 1 - Event Mask on line 1"]
    #[inline(always)]
    #[must_use]
    pub fn mr1(&mut self) -> Mr1W<EmrSpec> {
        Mr1W::new(self, 1)
    }
    #[doc = "Bit 2 - Event Mask on line 2"]
    #[inline(always)]
    #[must_use]
    pub fn mr2(&mut self) -> Mr2W<EmrSpec> {
        Mr2W::new(self, 2)
    }
    #[doc = "Bit 3 - Event Mask on line 3"]
    #[inline(always)]
    #[must_use]
    pub fn mr3(&mut self) -> Mr3W<EmrSpec> {
        Mr3W::new(self, 3)
    }
    #[doc = "Bit 4 - Event Mask on line 4"]
    #[inline(always)]
    #[must_use]
    pub fn mr4(&mut self) -> Mr4W<EmrSpec> {
        Mr4W::new(self, 4)
    }
    #[doc = "Bit 5 - Event Mask on line 5"]
    #[inline(always)]
    #[must_use]
    pub fn mr5(&mut self) -> Mr5W<EmrSpec> {
        Mr5W::new(self, 5)
    }
    #[doc = "Bit 6 - Event Mask on line 6"]
    #[inline(always)]
    #[must_use]
    pub fn mr6(&mut self) -> Mr6W<EmrSpec> {
        Mr6W::new(self, 6)
    }
    #[doc = "Bit 7 - Event Mask on line 7"]
    #[inline(always)]
    #[must_use]
    pub fn mr7(&mut self) -> Mr7W<EmrSpec> {
        Mr7W::new(self, 7)
    }
    #[doc = "Bit 8 - Event Mask on line 8"]
    #[inline(always)]
    #[must_use]
    pub fn mr8(&mut self) -> Mr8W<EmrSpec> {
        Mr8W::new(self, 8)
    }
    #[doc = "Bit 9 - Event Mask on line 9"]
    #[inline(always)]
    #[must_use]
    pub fn mr9(&mut self) -> Mr9W<EmrSpec> {
        Mr9W::new(self, 9)
    }
    #[doc = "Bit 10 - Event Mask on line 10"]
    #[inline(always)]
    #[must_use]
    pub fn mr10(&mut self) -> Mr10W<EmrSpec> {
        Mr10W::new(self, 10)
    }
    #[doc = "Bit 11 - Event Mask on line 11"]
    #[inline(always)]
    #[must_use]
    pub fn mr11(&mut self) -> Mr11W<EmrSpec> {
        Mr11W::new(self, 11)
    }
    #[doc = "Bit 12 - Event Mask on line 12"]
    #[inline(always)]
    #[must_use]
    pub fn mr12(&mut self) -> Mr12W<EmrSpec> {
        Mr12W::new(self, 12)
    }
    #[doc = "Bit 13 - Event Mask on line 13"]
    #[inline(always)]
    #[must_use]
    pub fn mr13(&mut self) -> Mr13W<EmrSpec> {
        Mr13W::new(self, 13)
    }
    #[doc = "Bit 14 - Event Mask on line 14"]
    #[inline(always)]
    #[must_use]
    pub fn mr14(&mut self) -> Mr14W<EmrSpec> {
        Mr14W::new(self, 14)
    }
    #[doc = "Bit 15 - Event Mask on line 15"]
    #[inline(always)]
    #[must_use]
    pub fn mr15(&mut self) -> Mr15W<EmrSpec> {
        Mr15W::new(self, 15)
    }
    #[doc = "Bit 16 - Event Mask on line 16"]
    #[inline(always)]
    #[must_use]
    pub fn mr16(&mut self) -> Mr16W<EmrSpec> {
        Mr16W::new(self, 16)
    }
    #[doc = "Bit 17 - Event Mask on line 17"]
    #[inline(always)]
    #[must_use]
    pub fn mr17(&mut self) -> Mr17W<EmrSpec> {
        Mr17W::new(self, 17)
    }
    #[doc = "Bit 18 - Event Mask on line 18"]
    #[inline(always)]
    #[must_use]
    pub fn mr18(&mut self) -> Mr18W<EmrSpec> {
        Mr18W::new(self, 18)
    }
    #[doc = "Bit 19 - Event Mask on line 19"]
    #[inline(always)]
    #[must_use]
    pub fn mr19(&mut self) -> Mr19W<EmrSpec> {
        Mr19W::new(self, 19)
    }
    #[doc = "Bit 20 - Event Mask on line 20"]
    #[inline(always)]
    #[must_use]
    pub fn mr20(&mut self) -> Mr20W<EmrSpec> {
        Mr20W::new(self, 20)
    }
    #[doc = "Bit 21 - Event Mask on line 21"]
    #[inline(always)]
    #[must_use]
    pub fn mr21(&mut self) -> Mr21W<EmrSpec> {
        Mr21W::new(self, 21)
    }
    #[doc = "Bit 22 - Event Mask on line 22"]
    #[inline(always)]
    #[must_use]
    pub fn mr22(&mut self) -> Mr22W<EmrSpec> {
        Mr22W::new(self, 22)
    }
}
#[doc = "Event mask register (EXTI_EMR)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`emr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`emr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EmrSpec;
impl crate::RegisterSpec for EmrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`emr::R`](R) reader structure"]
impl crate::Readable for EmrSpec {}
#[doc = "`write(|w| ..)` method takes [`emr::W`](W) writer structure"]
impl crate::Writable for EmrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets EMR to value 0"]
impl crate::Resettable for EmrSpec {
    const RESET_VALUE: u32 = 0;
}
