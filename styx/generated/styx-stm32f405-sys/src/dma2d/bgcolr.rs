// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BGCOLR` reader"]
pub type R = crate::R<BgcolrSpec>;
#[doc = "Register `BGCOLR` writer"]
pub type W = crate::W<BgcolrSpec>;
#[doc = "Field `BLUE` reader - Blue Value"]
pub type BlueR = crate::FieldReader;
#[doc = "Field `BLUE` writer - Blue Value"]
pub type BlueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `GREEN` reader - Green Value"]
pub type GreenR = crate::FieldReader;
#[doc = "Field `GREEN` writer - Green Value"]
pub type GreenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `RED` reader - Red Value"]
pub type RedR = crate::FieldReader;
#[doc = "Field `RED` writer - Red Value"]
pub type RedW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Blue Value"]
    #[inline(always)]
    pub fn blue(&self) -> BlueR {
        BlueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Green Value"]
    #[inline(always)]
    pub fn green(&self) -> GreenR {
        GreenR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Red Value"]
    #[inline(always)]
    pub fn red(&self) -> RedR {
        RedR::new(((self.bits >> 16) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Blue Value"]
    #[inline(always)]
    #[must_use]
    pub fn blue(&mut self) -> BlueW<BgcolrSpec> {
        BlueW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Green Value"]
    #[inline(always)]
    #[must_use]
    pub fn green(&mut self) -> GreenW<BgcolrSpec> {
        GreenW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Red Value"]
    #[inline(always)]
    #[must_use]
    pub fn red(&mut self) -> RedW<BgcolrSpec> {
        RedW::new(self, 16)
    }
}
#[doc = "background color register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgcolr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgcolr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BgcolrSpec;
impl crate::RegisterSpec for BgcolrSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`bgcolr::R`](R) reader structure"]
impl crate::Readable for BgcolrSpec {}
#[doc = "`write(|w| ..)` method takes [`bgcolr::W`](W) writer structure"]
impl crate::Writable for BgcolrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BGCOLR to value 0"]
impl crate::Resettable for BgcolrSpec {
    const RESET_VALUE: u32 = 0;
}
