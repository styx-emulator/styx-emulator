// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1CLUTWR` reader"]
pub type R = crate::R<L1clutwrSpec>;
#[doc = "Register `L1CLUTWR` writer"]
pub type W = crate::W<L1clutwrSpec>;
#[doc = "Field `BLUE` reader - Blue value"]
pub type BlueR = crate::FieldReader;
#[doc = "Field `BLUE` writer - Blue value"]
pub type BlueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `GREEN` reader - Green value"]
pub type GreenR = crate::FieldReader;
#[doc = "Field `GREEN` writer - Green value"]
pub type GreenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `RED` reader - Red value"]
pub type RedR = crate::FieldReader;
#[doc = "Field `RED` writer - Red value"]
pub type RedW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `CLUTADD` reader - CLUT Address"]
pub type ClutaddR = crate::FieldReader;
#[doc = "Field `CLUTADD` writer - CLUT Address"]
pub type ClutaddW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Blue value"]
    #[inline(always)]
    pub fn blue(&self) -> BlueR {
        BlueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Green value"]
    #[inline(always)]
    pub fn green(&self) -> GreenR {
        GreenR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Red value"]
    #[inline(always)]
    pub fn red(&self) -> RedR {
        RedR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - CLUT Address"]
    #[inline(always)]
    pub fn clutadd(&self) -> ClutaddR {
        ClutaddR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Blue value"]
    #[inline(always)]
    #[must_use]
    pub fn blue(&mut self) -> BlueW<L1clutwrSpec> {
        BlueW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Green value"]
    #[inline(always)]
    #[must_use]
    pub fn green(&mut self) -> GreenW<L1clutwrSpec> {
        GreenW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Red value"]
    #[inline(always)]
    #[must_use]
    pub fn red(&mut self) -> RedW<L1clutwrSpec> {
        RedW::new(self, 16)
    }
    #[doc = "Bits 24:31 - CLUT Address"]
    #[inline(always)]
    #[must_use]
    pub fn clutadd(&mut self) -> ClutaddW<L1clutwrSpec> {
        ClutaddW::new(self, 24)
    }
}
#[doc = "Layerx CLUT Write Register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1clutwr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1clutwrSpec;
impl crate::RegisterSpec for L1clutwrSpec {
    type Ux = u32;
    const OFFSET: u64 = 196u64;
}
#[doc = "`write(|w| ..)` method takes [`l1clutwr::W`](W) writer structure"]
impl crate::Writable for L1clutwrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1CLUTWR to value 0"]
impl crate::Resettable for L1clutwrSpec {
    const RESET_VALUE: u32 = 0;
}
