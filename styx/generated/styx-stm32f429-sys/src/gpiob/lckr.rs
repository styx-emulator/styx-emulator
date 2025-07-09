// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LCKR` reader"]
pub type R = crate::R<LckrSpec>;
#[doc = "Register `LCKR` writer"]
pub type W = crate::W<LckrSpec>;
#[doc = "Field `LCK0` reader - Port x lock bit y (y= 0..15)"]
pub type Lck0R = crate::BitReader;
#[doc = "Field `LCK0` writer - Port x lock bit y (y= 0..15)"]
pub type Lck0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK1` reader - Port x lock bit y (y= 0..15)"]
pub type Lck1R = crate::BitReader;
#[doc = "Field `LCK1` writer - Port x lock bit y (y= 0..15)"]
pub type Lck1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK2` reader - Port x lock bit y (y= 0..15)"]
pub type Lck2R = crate::BitReader;
#[doc = "Field `LCK2` writer - Port x lock bit y (y= 0..15)"]
pub type Lck2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK3` reader - Port x lock bit y (y= 0..15)"]
pub type Lck3R = crate::BitReader;
#[doc = "Field `LCK3` writer - Port x lock bit y (y= 0..15)"]
pub type Lck3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK4` reader - Port x lock bit y (y= 0..15)"]
pub type Lck4R = crate::BitReader;
#[doc = "Field `LCK4` writer - Port x lock bit y (y= 0..15)"]
pub type Lck4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK5` reader - Port x lock bit y (y= 0..15)"]
pub type Lck5R = crate::BitReader;
#[doc = "Field `LCK5` writer - Port x lock bit y (y= 0..15)"]
pub type Lck5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK6` reader - Port x lock bit y (y= 0..15)"]
pub type Lck6R = crate::BitReader;
#[doc = "Field `LCK6` writer - Port x lock bit y (y= 0..15)"]
pub type Lck6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK7` reader - Port x lock bit y (y= 0..15)"]
pub type Lck7R = crate::BitReader;
#[doc = "Field `LCK7` writer - Port x lock bit y (y= 0..15)"]
pub type Lck7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK8` reader - Port x lock bit y (y= 0..15)"]
pub type Lck8R = crate::BitReader;
#[doc = "Field `LCK8` writer - Port x lock bit y (y= 0..15)"]
pub type Lck8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK9` reader - Port x lock bit y (y= 0..15)"]
pub type Lck9R = crate::BitReader;
#[doc = "Field `LCK9` writer - Port x lock bit y (y= 0..15)"]
pub type Lck9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK10` reader - Port x lock bit y (y= 0..15)"]
pub type Lck10R = crate::BitReader;
#[doc = "Field `LCK10` writer - Port x lock bit y (y= 0..15)"]
pub type Lck10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK11` reader - Port x lock bit y (y= 0..15)"]
pub type Lck11R = crate::BitReader;
#[doc = "Field `LCK11` writer - Port x lock bit y (y= 0..15)"]
pub type Lck11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK12` reader - Port x lock bit y (y= 0..15)"]
pub type Lck12R = crate::BitReader;
#[doc = "Field `LCK12` writer - Port x lock bit y (y= 0..15)"]
pub type Lck12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK13` reader - Port x lock bit y (y= 0..15)"]
pub type Lck13R = crate::BitReader;
#[doc = "Field `LCK13` writer - Port x lock bit y (y= 0..15)"]
pub type Lck13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK14` reader - Port x lock bit y (y= 0..15)"]
pub type Lck14R = crate::BitReader;
#[doc = "Field `LCK14` writer - Port x lock bit y (y= 0..15)"]
pub type Lck14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCK15` reader - Port x lock bit y (y= 0..15)"]
pub type Lck15R = crate::BitReader;
#[doc = "Field `LCK15` writer - Port x lock bit y (y= 0..15)"]
pub type Lck15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LCKK` reader - Port x lock bit y (y= 0..15)"]
pub type LckkR = crate::BitReader;
#[doc = "Field `LCKK` writer - Port x lock bit y (y= 0..15)"]
pub type LckkW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck0(&self) -> Lck0R {
        Lck0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck1(&self) -> Lck1R {
        Lck1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck2(&self) -> Lck2R {
        Lck2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck3(&self) -> Lck3R {
        Lck3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck4(&self) -> Lck4R {
        Lck4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck5(&self) -> Lck5R {
        Lck5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck6(&self) -> Lck6R {
        Lck6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck7(&self) -> Lck7R {
        Lck7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck8(&self) -> Lck8R {
        Lck8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck9(&self) -> Lck9R {
        Lck9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck10(&self) -> Lck10R {
        Lck10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck11(&self) -> Lck11R {
        Lck11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck12(&self) -> Lck12R {
        Lck12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck13(&self) -> Lck13R {
        Lck13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck14(&self) -> Lck14R {
        Lck14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lck15(&self) -> Lck15R {
        Lck15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    pub fn lckk(&self) -> LckkR {
        LckkR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck0(&mut self) -> Lck0W<LckrSpec> {
        Lck0W::new(self, 0)
    }
    #[doc = "Bit 1 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck1(&mut self) -> Lck1W<LckrSpec> {
        Lck1W::new(self, 1)
    }
    #[doc = "Bit 2 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck2(&mut self) -> Lck2W<LckrSpec> {
        Lck2W::new(self, 2)
    }
    #[doc = "Bit 3 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck3(&mut self) -> Lck3W<LckrSpec> {
        Lck3W::new(self, 3)
    }
    #[doc = "Bit 4 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck4(&mut self) -> Lck4W<LckrSpec> {
        Lck4W::new(self, 4)
    }
    #[doc = "Bit 5 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck5(&mut self) -> Lck5W<LckrSpec> {
        Lck5W::new(self, 5)
    }
    #[doc = "Bit 6 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck6(&mut self) -> Lck6W<LckrSpec> {
        Lck6W::new(self, 6)
    }
    #[doc = "Bit 7 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck7(&mut self) -> Lck7W<LckrSpec> {
        Lck7W::new(self, 7)
    }
    #[doc = "Bit 8 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck8(&mut self) -> Lck8W<LckrSpec> {
        Lck8W::new(self, 8)
    }
    #[doc = "Bit 9 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck9(&mut self) -> Lck9W<LckrSpec> {
        Lck9W::new(self, 9)
    }
    #[doc = "Bit 10 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck10(&mut self) -> Lck10W<LckrSpec> {
        Lck10W::new(self, 10)
    }
    #[doc = "Bit 11 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck11(&mut self) -> Lck11W<LckrSpec> {
        Lck11W::new(self, 11)
    }
    #[doc = "Bit 12 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck12(&mut self) -> Lck12W<LckrSpec> {
        Lck12W::new(self, 12)
    }
    #[doc = "Bit 13 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck13(&mut self) -> Lck13W<LckrSpec> {
        Lck13W::new(self, 13)
    }
    #[doc = "Bit 14 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck14(&mut self) -> Lck14W<LckrSpec> {
        Lck14W::new(self, 14)
    }
    #[doc = "Bit 15 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lck15(&mut self) -> Lck15W<LckrSpec> {
        Lck15W::new(self, 15)
    }
    #[doc = "Bit 16 - Port x lock bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn lckk(&mut self) -> LckkW<LckrSpec> {
        LckkW::new(self, 16)
    }
}
#[doc = "GPIO port configuration lock register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lckr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lckr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LckrSpec;
impl crate::RegisterSpec for LckrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`lckr::R`](R) reader structure"]
impl crate::Readable for LckrSpec {}
#[doc = "`write(|w| ..)` method takes [`lckr::W`](W) writer structure"]
impl crate::Writable for LckrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets LCKR to value 0"]
impl crate::Resettable for LckrSpec {
    const RESET_VALUE: u32 = 0;
}
