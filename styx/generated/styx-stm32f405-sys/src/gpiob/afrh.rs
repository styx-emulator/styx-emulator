// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AFRH` reader"]
pub type R = crate::R<AfrhSpec>;
#[doc = "Register `AFRH` writer"]
pub type W = crate::W<AfrhSpec>;
#[doc = "Field `AFRH8` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh8R = crate::FieldReader;
#[doc = "Field `AFRH8` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh8W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH9` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh9R = crate::FieldReader;
#[doc = "Field `AFRH9` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh9W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH10` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh10R = crate::FieldReader;
#[doc = "Field `AFRH10` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh10W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH11` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh11R = crate::FieldReader;
#[doc = "Field `AFRH11` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh11W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH12` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh12R = crate::FieldReader;
#[doc = "Field `AFRH12` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh12W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH13` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh13R = crate::FieldReader;
#[doc = "Field `AFRH13` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh13W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH14` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh14R = crate::FieldReader;
#[doc = "Field `AFRH14` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh14W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `AFRH15` reader - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh15R = crate::FieldReader;
#[doc = "Field `AFRH15` writer - Alternate function selection for port x bit y (y = 8..15)"]
pub type Afrh15W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh8(&self) -> Afrh8R {
        Afrh8R::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh9(&self) -> Afrh9R {
        Afrh9R::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh10(&self) -> Afrh10R {
        Afrh10R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:15 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh11(&self) -> Afrh11R {
        Afrh11R::new(((self.bits >> 12) & 0x0f) as u8)
    }
    #[doc = "Bits 16:19 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh12(&self) -> Afrh12R {
        Afrh12R::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh13(&self) -> Afrh13R {
        Afrh13R::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bits 24:27 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh14(&self) -> Afrh14R {
        Afrh14R::new(((self.bits >> 24) & 0x0f) as u8)
    }
    #[doc = "Bits 28:31 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    pub fn afrh15(&self) -> Afrh15R {
        Afrh15R::new(((self.bits >> 28) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh8(&mut self) -> Afrh8W<AfrhSpec> {
        Afrh8W::new(self, 0)
    }
    #[doc = "Bits 4:7 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh9(&mut self) -> Afrh9W<AfrhSpec> {
        Afrh9W::new(self, 4)
    }
    #[doc = "Bits 8:11 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh10(&mut self) -> Afrh10W<AfrhSpec> {
        Afrh10W::new(self, 8)
    }
    #[doc = "Bits 12:15 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh11(&mut self) -> Afrh11W<AfrhSpec> {
        Afrh11W::new(self, 12)
    }
    #[doc = "Bits 16:19 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh12(&mut self) -> Afrh12W<AfrhSpec> {
        Afrh12W::new(self, 16)
    }
    #[doc = "Bits 20:23 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh13(&mut self) -> Afrh13W<AfrhSpec> {
        Afrh13W::new(self, 20)
    }
    #[doc = "Bits 24:27 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh14(&mut self) -> Afrh14W<AfrhSpec> {
        Afrh14W::new(self, 24)
    }
    #[doc = "Bits 28:31 - Alternate function selection for port x bit y (y = 8..15)"]
    #[inline(always)]
    #[must_use]
    pub fn afrh15(&mut self) -> Afrh15W<AfrhSpec> {
        Afrh15W::new(self, 28)
    }
}
#[doc = "GPIO alternate function high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`afrh::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`afrh::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AfrhSpec;
impl crate::RegisterSpec for AfrhSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`afrh::R`](R) reader structure"]
impl crate::Readable for AfrhSpec {}
#[doc = "`write(|w| ..)` method takes [`afrh::W`](W) writer structure"]
impl crate::Writable for AfrhSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AFRH to value 0"]
impl crate::Resettable for AfrhSpec {
    const RESET_VALUE: u32 = 0;
}
