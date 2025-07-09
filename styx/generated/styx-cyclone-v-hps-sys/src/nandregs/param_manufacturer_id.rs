// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_manufacturer_id` reader"]
pub type R = crate::R<ParamManufacturerIdSpec>;
#[doc = "Register `param_manufacturer_id` writer"]
pub type W = crate::W<ParamManufacturerIdSpec>;
#[doc = "Field `value` reader - Manufacturer ID"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Manufacturer ID"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Manufacturer ID"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Manufacturer ID"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamManufacturerIdSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_manufacturer_id::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`param_manufacturer_id::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamManufacturerIdSpec;
impl crate::RegisterSpec for ParamManufacturerIdSpec {
    type Ux = u32;
    const OFFSET: u64 = 768u64;
}
#[doc = "`read()` method returns [`param_manufacturer_id::R`](R) reader structure"]
impl crate::Readable for ParamManufacturerIdSpec {}
#[doc = "`write(|w| ..)` method takes [`param_manufacturer_id::W`](W) writer structure"]
impl crate::Writable for ParamManufacturerIdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets param_manufacturer_id to value 0"]
impl crate::Resettable for ParamManufacturerIdSpec {
    const RESET_VALUE: u32 = 0;
}
