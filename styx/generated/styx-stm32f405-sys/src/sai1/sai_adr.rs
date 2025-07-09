// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SAI_ADR` reader"]
pub type R = crate::R<SaiAdrSpec>;
#[doc = "Register `SAI_ADR` writer"]
pub type W = crate::W<SaiAdrSpec>;
#[doc = "Field `DATA` reader - Data"]
pub type DataR = crate::FieldReader<u32>;
#[doc = "Field `DATA` writer - Data"]
pub type DataW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Data"]
    #[inline(always)]
    pub fn data(&self) -> DataR {
        DataR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Data"]
    #[inline(always)]
    #[must_use]
    pub fn data(&mut self) -> DataW<SaiAdrSpec> {
        DataW::new(self, 0)
    }
}
#[doc = "SAI AData register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_adr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_adr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiAdrSpec;
impl crate::RegisterSpec for SaiAdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`sai_adr::R`](R) reader structure"]
impl crate::Readable for SaiAdrSpec {}
#[doc = "`write(|w| ..)` method takes [`sai_adr::W`](W) writer structure"]
impl crate::Writable for SaiAdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SAI_ADR to value 0"]
impl crate::Resettable for SaiAdrSpec {
    const RESET_VALUE: u32 = 0;
}
