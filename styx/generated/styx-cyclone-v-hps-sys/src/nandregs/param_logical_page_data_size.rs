// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `param_logical_page_data_size` reader"]
pub type R = crate::R<ParamLogicalPageDataSizeSpec>;
#[doc = "Register `param_logical_page_data_size` writer"]
pub type W = crate::W<ParamLogicalPageDataSizeSpec>;
#[doc = "Field `value` reader - Logical page spare area size in bytes. If multiple devices are connected on a single chip select, physical page data size will be multiplied by the number of devices to arrive at logical page size."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Logical page spare area size in bytes. If multiple devices are connected on a single chip select, physical page data size will be multiplied by the number of devices to arrive at logical page size."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Logical page spare area size in bytes. If multiple devices are connected on a single chip select, physical page data size will be multiplied by the number of devices to arrive at logical page size."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Logical page spare area size in bytes. If multiple devices are connected on a single chip select, physical page data size will be multiplied by the number of devices to arrive at logical page size."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamLogicalPageDataSizeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Logical page data area size in bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_logical_page_data_size::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamLogicalPageDataSizeSpec;
impl crate::RegisterSpec for ParamLogicalPageDataSizeSpec {
    type Ux = u32;
    const OFFSET: u64 = 848u64;
}
#[doc = "`read()` method returns [`param_logical_page_data_size::R`](R) reader structure"]
impl crate::Readable for ParamLogicalPageDataSizeSpec {}
#[doc = "`reset()` method sets param_logical_page_data_size to value 0"]
impl crate::Resettable for ParamLogicalPageDataSizeSpec {
    const RESET_VALUE: u32 = 0;
}
