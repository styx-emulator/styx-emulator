// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ODR` reader"]
pub type R = crate::R<OdrSpec>;
#[doc = "Register `ODR` writer"]
pub type W = crate::W<OdrSpec>;
#[doc = "Field `ODR0` reader - Port output data (y = 0..15)"]
pub type Odr0R = crate::BitReader;
#[doc = "Field `ODR0` writer - Port output data (y = 0..15)"]
pub type Odr0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR1` reader - Port output data (y = 0..15)"]
pub type Odr1R = crate::BitReader;
#[doc = "Field `ODR1` writer - Port output data (y = 0..15)"]
pub type Odr1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR2` reader - Port output data (y = 0..15)"]
pub type Odr2R = crate::BitReader;
#[doc = "Field `ODR2` writer - Port output data (y = 0..15)"]
pub type Odr2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR3` reader - Port output data (y = 0..15)"]
pub type Odr3R = crate::BitReader;
#[doc = "Field `ODR3` writer - Port output data (y = 0..15)"]
pub type Odr3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR4` reader - Port output data (y = 0..15)"]
pub type Odr4R = crate::BitReader;
#[doc = "Field `ODR4` writer - Port output data (y = 0..15)"]
pub type Odr4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR5` reader - Port output data (y = 0..15)"]
pub type Odr5R = crate::BitReader;
#[doc = "Field `ODR5` writer - Port output data (y = 0..15)"]
pub type Odr5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR6` reader - Port output data (y = 0..15)"]
pub type Odr6R = crate::BitReader;
#[doc = "Field `ODR6` writer - Port output data (y = 0..15)"]
pub type Odr6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR7` reader - Port output data (y = 0..15)"]
pub type Odr7R = crate::BitReader;
#[doc = "Field `ODR7` writer - Port output data (y = 0..15)"]
pub type Odr7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR8` reader - Port output data (y = 0..15)"]
pub type Odr8R = crate::BitReader;
#[doc = "Field `ODR8` writer - Port output data (y = 0..15)"]
pub type Odr8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR9` reader - Port output data (y = 0..15)"]
pub type Odr9R = crate::BitReader;
#[doc = "Field `ODR9` writer - Port output data (y = 0..15)"]
pub type Odr9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR10` reader - Port output data (y = 0..15)"]
pub type Odr10R = crate::BitReader;
#[doc = "Field `ODR10` writer - Port output data (y = 0..15)"]
pub type Odr10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR11` reader - Port output data (y = 0..15)"]
pub type Odr11R = crate::BitReader;
#[doc = "Field `ODR11` writer - Port output data (y = 0..15)"]
pub type Odr11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR12` reader - Port output data (y = 0..15)"]
pub type Odr12R = crate::BitReader;
#[doc = "Field `ODR12` writer - Port output data (y = 0..15)"]
pub type Odr12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR13` reader - Port output data (y = 0..15)"]
pub type Odr13R = crate::BitReader;
#[doc = "Field `ODR13` writer - Port output data (y = 0..15)"]
pub type Odr13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR14` reader - Port output data (y = 0..15)"]
pub type Odr14R = crate::BitReader;
#[doc = "Field `ODR14` writer - Port output data (y = 0..15)"]
pub type Odr14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODR15` reader - Port output data (y = 0..15)"]
pub type Odr15R = crate::BitReader;
#[doc = "Field `ODR15` writer - Port output data (y = 0..15)"]
pub type Odr15W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr0(&self) -> Odr0R {
        Odr0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr1(&self) -> Odr1R {
        Odr1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr2(&self) -> Odr2R {
        Odr2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr3(&self) -> Odr3R {
        Odr3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr4(&self) -> Odr4R {
        Odr4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr5(&self) -> Odr5R {
        Odr5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr6(&self) -> Odr6R {
        Odr6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr7(&self) -> Odr7R {
        Odr7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr8(&self) -> Odr8R {
        Odr8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr9(&self) -> Odr9R {
        Odr9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr10(&self) -> Odr10R {
        Odr10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr11(&self) -> Odr11R {
        Odr11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr12(&self) -> Odr12R {
        Odr12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr13(&self) -> Odr13R {
        Odr13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr14(&self) -> Odr14R {
        Odr14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Port output data (y = 0..15)"]
    #[inline(always)]
    pub fn odr15(&self) -> Odr15R {
        Odr15R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr0(&mut self) -> Odr0W<OdrSpec> {
        Odr0W::new(self, 0)
    }
    #[doc = "Bit 1 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr1(&mut self) -> Odr1W<OdrSpec> {
        Odr1W::new(self, 1)
    }
    #[doc = "Bit 2 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr2(&mut self) -> Odr2W<OdrSpec> {
        Odr2W::new(self, 2)
    }
    #[doc = "Bit 3 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr3(&mut self) -> Odr3W<OdrSpec> {
        Odr3W::new(self, 3)
    }
    #[doc = "Bit 4 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr4(&mut self) -> Odr4W<OdrSpec> {
        Odr4W::new(self, 4)
    }
    #[doc = "Bit 5 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr5(&mut self) -> Odr5W<OdrSpec> {
        Odr5W::new(self, 5)
    }
    #[doc = "Bit 6 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr6(&mut self) -> Odr6W<OdrSpec> {
        Odr6W::new(self, 6)
    }
    #[doc = "Bit 7 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr7(&mut self) -> Odr7W<OdrSpec> {
        Odr7W::new(self, 7)
    }
    #[doc = "Bit 8 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr8(&mut self) -> Odr8W<OdrSpec> {
        Odr8W::new(self, 8)
    }
    #[doc = "Bit 9 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr9(&mut self) -> Odr9W<OdrSpec> {
        Odr9W::new(self, 9)
    }
    #[doc = "Bit 10 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr10(&mut self) -> Odr10W<OdrSpec> {
        Odr10W::new(self, 10)
    }
    #[doc = "Bit 11 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr11(&mut self) -> Odr11W<OdrSpec> {
        Odr11W::new(self, 11)
    }
    #[doc = "Bit 12 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr12(&mut self) -> Odr12W<OdrSpec> {
        Odr12W::new(self, 12)
    }
    #[doc = "Bit 13 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr13(&mut self) -> Odr13W<OdrSpec> {
        Odr13W::new(self, 13)
    }
    #[doc = "Bit 14 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr14(&mut self) -> Odr14W<OdrSpec> {
        Odr14W::new(self, 14)
    }
    #[doc = "Bit 15 - Port output data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn odr15(&mut self) -> Odr15W<OdrSpec> {
        Odr15W::new(self, 15)
    }
}
#[doc = "GPIO port output data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`odr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`odr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OdrSpec;
impl crate::RegisterSpec for OdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`odr::R`](R) reader structure"]
impl crate::Readable for OdrSpec {}
#[doc = "`write(|w| ..)` method takes [`odr::W`](W) writer structure"]
impl crate::Writable for OdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ODR to value 0"]
impl crate::Resettable for OdrSpec {
    const RESET_VALUE: u32 = 0;
}
