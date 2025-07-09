// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OSPEEDR` reader"]
pub type R = crate::R<OspeedrSpec>;
#[doc = "Register `OSPEEDR` writer"]
pub type W = crate::W<OspeedrSpec>;
#[doc = "Field `OSPEEDR0` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr0R = crate::FieldReader;
#[doc = "Field `OSPEEDR0` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr0W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR1` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr1R = crate::FieldReader;
#[doc = "Field `OSPEEDR1` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr1W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR2` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr2R = crate::FieldReader;
#[doc = "Field `OSPEEDR2` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr2W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR3` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr3R = crate::FieldReader;
#[doc = "Field `OSPEEDR3` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr3W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR4` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr4R = crate::FieldReader;
#[doc = "Field `OSPEEDR4` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr4W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR5` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr5R = crate::FieldReader;
#[doc = "Field `OSPEEDR5` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr5W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR6` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr6R = crate::FieldReader;
#[doc = "Field `OSPEEDR6` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr6W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR7` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr7R = crate::FieldReader;
#[doc = "Field `OSPEEDR7` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr7W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR8` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr8R = crate::FieldReader;
#[doc = "Field `OSPEEDR8` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr8W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR9` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr9R = crate::FieldReader;
#[doc = "Field `OSPEEDR9` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr9W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR10` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr10R = crate::FieldReader;
#[doc = "Field `OSPEEDR10` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr10W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR11` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr11R = crate::FieldReader;
#[doc = "Field `OSPEEDR11` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr11W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR12` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr12R = crate::FieldReader;
#[doc = "Field `OSPEEDR12` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr12W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR13` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr13R = crate::FieldReader;
#[doc = "Field `OSPEEDR13` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr13W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR14` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr14R = crate::FieldReader;
#[doc = "Field `OSPEEDR14` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr14W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OSPEEDR15` reader - Port x configuration bits (y = 0..15)"]
pub type Ospeedr15R = crate::FieldReader;
#[doc = "Field `OSPEEDR15` writer - Port x configuration bits (y = 0..15)"]
pub type Ospeedr15W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr0(&self) -> Ospeedr0R {
        Ospeedr0R::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr1(&self) -> Ospeedr1R {
        Ospeedr1R::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr2(&self) -> Ospeedr2R {
        Ospeedr2R::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bits 6:7 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr3(&self) -> Ospeedr3R {
        Ospeedr3R::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 8:9 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr4(&self) -> Ospeedr4R {
        Ospeedr4R::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:11 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr5(&self) -> Ospeedr5R {
        Ospeedr5R::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bits 12:13 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr6(&self) -> Ospeedr6R {
        Ospeedr6R::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 14:15 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr7(&self) -> Ospeedr7R {
        Ospeedr7R::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bits 16:17 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr8(&self) -> Ospeedr8R {
        Ospeedr8R::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 18:19 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr9(&self) -> Ospeedr9R {
        Ospeedr9R::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bits 20:21 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr10(&self) -> Ospeedr10R {
        Ospeedr10R::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bits 22:23 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr11(&self) -> Ospeedr11R {
        Ospeedr11R::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bits 24:25 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr12(&self) -> Ospeedr12R {
        Ospeedr12R::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bits 26:27 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr13(&self) -> Ospeedr13R {
        Ospeedr13R::new(((self.bits >> 26) & 3) as u8)
    }
    #[doc = "Bits 28:29 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr14(&self) -> Ospeedr14R {
        Ospeedr14R::new(((self.bits >> 28) & 3) as u8)
    }
    #[doc = "Bits 30:31 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ospeedr15(&self) -> Ospeedr15R {
        Ospeedr15R::new(((self.bits >> 30) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr0(&mut self) -> Ospeedr0W<OspeedrSpec> {
        Ospeedr0W::new(self, 0)
    }
    #[doc = "Bits 2:3 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr1(&mut self) -> Ospeedr1W<OspeedrSpec> {
        Ospeedr1W::new(self, 2)
    }
    #[doc = "Bits 4:5 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr2(&mut self) -> Ospeedr2W<OspeedrSpec> {
        Ospeedr2W::new(self, 4)
    }
    #[doc = "Bits 6:7 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr3(&mut self) -> Ospeedr3W<OspeedrSpec> {
        Ospeedr3W::new(self, 6)
    }
    #[doc = "Bits 8:9 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr4(&mut self) -> Ospeedr4W<OspeedrSpec> {
        Ospeedr4W::new(self, 8)
    }
    #[doc = "Bits 10:11 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr5(&mut self) -> Ospeedr5W<OspeedrSpec> {
        Ospeedr5W::new(self, 10)
    }
    #[doc = "Bits 12:13 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr6(&mut self) -> Ospeedr6W<OspeedrSpec> {
        Ospeedr6W::new(self, 12)
    }
    #[doc = "Bits 14:15 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr7(&mut self) -> Ospeedr7W<OspeedrSpec> {
        Ospeedr7W::new(self, 14)
    }
    #[doc = "Bits 16:17 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr8(&mut self) -> Ospeedr8W<OspeedrSpec> {
        Ospeedr8W::new(self, 16)
    }
    #[doc = "Bits 18:19 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr9(&mut self) -> Ospeedr9W<OspeedrSpec> {
        Ospeedr9W::new(self, 18)
    }
    #[doc = "Bits 20:21 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr10(&mut self) -> Ospeedr10W<OspeedrSpec> {
        Ospeedr10W::new(self, 20)
    }
    #[doc = "Bits 22:23 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr11(&mut self) -> Ospeedr11W<OspeedrSpec> {
        Ospeedr11W::new(self, 22)
    }
    #[doc = "Bits 24:25 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr12(&mut self) -> Ospeedr12W<OspeedrSpec> {
        Ospeedr12W::new(self, 24)
    }
    #[doc = "Bits 26:27 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr13(&mut self) -> Ospeedr13W<OspeedrSpec> {
        Ospeedr13W::new(self, 26)
    }
    #[doc = "Bits 28:29 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr14(&mut self) -> Ospeedr14W<OspeedrSpec> {
        Ospeedr14W::new(self, 28)
    }
    #[doc = "Bits 30:31 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ospeedr15(&mut self) -> Ospeedr15W<OspeedrSpec> {
        Ospeedr15W::new(self, 30)
    }
}
#[doc = "GPIO port output speed register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ospeedr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ospeedr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OspeedrSpec;
impl crate::RegisterSpec for OspeedrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ospeedr::R`](R) reader structure"]
impl crate::Readable for OspeedrSpec {}
#[doc = "`write(|w| ..)` method takes [`ospeedr::W`](W) writer structure"]
impl crate::Writable for OspeedrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OSPEEDR to value 0"]
impl crate::Resettable for OspeedrSpec {
    const RESET_VALUE: u32 = 0;
}
