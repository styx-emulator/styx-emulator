// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DIN` reader"]
pub type R = crate::R<DinSpec>;
#[doc = "Register `DIN` writer"]
pub type W = crate::W<DinSpec>;
#[doc = "Field `DATAIN` reader - Data input"]
pub type DatainR = crate::FieldReader<u32>;
#[doc = "Field `DATAIN` writer - Data input"]
pub type DatainW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Data input"]
    #[inline(always)]
    pub fn datain(&self) -> DatainR {
        DatainR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Data input"]
    #[inline(always)]
    #[must_use]
    pub fn datain(&mut self) -> DatainW<DinSpec> {
        DatainW::new(self, 0)
    }
}
#[doc = "data input register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`din::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`din::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DinSpec;
impl crate::RegisterSpec for DinSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`din::R`](R) reader structure"]
impl crate::Readable for DinSpec {}
#[doc = "`write(|w| ..)` method takes [`din::W`](W) writer structure"]
impl crate::Writable for DinSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DIN to value 0"]
impl crate::Resettable for DinSpec {
    const RESET_VALUE: u32 = 0;
}
