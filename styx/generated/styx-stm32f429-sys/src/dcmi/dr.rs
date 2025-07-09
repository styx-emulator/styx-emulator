// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DR` reader"]
pub type R = crate::R<DrSpec>;
#[doc = "Register `DR` writer"]
pub type W = crate::W<DrSpec>;
#[doc = "Field `Byte0` reader - Data byte 0"]
pub type Byte0R = crate::FieldReader;
#[doc = "Field `Byte0` writer - Data byte 0"]
pub type Byte0W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Byte1` reader - Data byte 1"]
pub type Byte1R = crate::FieldReader;
#[doc = "Field `Byte1` writer - Data byte 1"]
pub type Byte1W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Byte2` reader - Data byte 2"]
pub type Byte2R = crate::FieldReader;
#[doc = "Field `Byte2` writer - Data byte 2"]
pub type Byte2W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Byte3` reader - Data byte 3"]
pub type Byte3R = crate::FieldReader;
#[doc = "Field `Byte3` writer - Data byte 3"]
pub type Byte3W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Data byte 0"]
    #[inline(always)]
    pub fn byte0(&self) -> Byte0R {
        Byte0R::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Data byte 1"]
    #[inline(always)]
    pub fn byte1(&self) -> Byte1R {
        Byte1R::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Data byte 2"]
    #[inline(always)]
    pub fn byte2(&self) -> Byte2R {
        Byte2R::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - Data byte 3"]
    #[inline(always)]
    pub fn byte3(&self) -> Byte3R {
        Byte3R::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Data byte 0"]
    #[inline(always)]
    #[must_use]
    pub fn byte0(&mut self) -> Byte0W<DrSpec> {
        Byte0W::new(self, 0)
    }
    #[doc = "Bits 8:15 - Data byte 1"]
    #[inline(always)]
    #[must_use]
    pub fn byte1(&mut self) -> Byte1W<DrSpec> {
        Byte1W::new(self, 8)
    }
    #[doc = "Bits 16:23 - Data byte 2"]
    #[inline(always)]
    #[must_use]
    pub fn byte2(&mut self) -> Byte2W<DrSpec> {
        Byte2W::new(self, 16)
    }
    #[doc = "Bits 24:31 - Data byte 3"]
    #[inline(always)]
    #[must_use]
    pub fn byte3(&mut self) -> Byte3W<DrSpec> {
        Byte3W::new(self, 24)
    }
}
#[doc = "data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DrSpec;
impl crate::RegisterSpec for DrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`dr::R`](R) reader structure"]
impl crate::Readable for DrSpec {}
#[doc = "`reset()` method sets DR to value 0"]
impl crate::Resettable for DrSpec {
    const RESET_VALUE: u32 = 0;
}
