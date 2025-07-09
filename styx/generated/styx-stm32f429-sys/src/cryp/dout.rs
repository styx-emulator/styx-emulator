// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DOUT` reader"]
pub type R = crate::R<DoutSpec>;
#[doc = "Register `DOUT` writer"]
pub type W = crate::W<DoutSpec>;
#[doc = "Field `DATAOUT` reader - Data output"]
pub type DataoutR = crate::FieldReader<u32>;
#[doc = "Field `DATAOUT` writer - Data output"]
pub type DataoutW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Data output"]
    #[inline(always)]
    pub fn dataout(&self) -> DataoutR {
        DataoutR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Data output"]
    #[inline(always)]
    #[must_use]
    pub fn dataout(&mut self) -> DataoutW<DoutSpec> {
        DataoutW::new(self, 0)
    }
}
#[doc = "data output register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dout::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DoutSpec;
impl crate::RegisterSpec for DoutSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`dout::R`](R) reader structure"]
impl crate::Readable for DoutSpec {}
#[doc = "`reset()` method sets DOUT to value 0"]
impl crate::Resettable for DoutSpec {
    const RESET_VALUE: u32 = 0;
}
