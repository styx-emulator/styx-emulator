// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `flashcmdrddataup` reader"]
pub type R = crate::R<FlashcmdrddataupSpec>;
#[doc = "Register `flashcmdrddataup` writer"]
pub type W = crate::W<FlashcmdrddataupSpec>;
#[doc = "Field `data` reader - This is the data that is returned by the FLASH device for any status or configuration read operation carried out by triggering the event in the control register. The register will be valid when the polling bit in the control register is low."]
pub type DataR = crate::FieldReader<u32>;
#[doc = "Field `data` writer - This is the data that is returned by the FLASH device for any status or configuration read operation carried out by triggering the event in the control register. The register will be valid when the polling bit in the control register is low."]
pub type DataW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This is the data that is returned by the FLASH device for any status or configuration read operation carried out by triggering the event in the control register. The register will be valid when the polling bit in the control register is low."]
    #[inline(always)]
    pub fn data(&self) -> DataR {
        DataR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This is the data that is returned by the FLASH device for any status or configuration read operation carried out by triggering the event in the control register. The register will be valid when the polling bit in the control register is low."]
    #[inline(always)]
    #[must_use]
    pub fn data(&mut self) -> DataW<FlashcmdrddataupSpec> {
        DataW::new(self, 0)
    }
}
#[doc = "Device Instruction Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdrddataup::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdrddataup::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FlashcmdrddataupSpec;
impl crate::RegisterSpec for FlashcmdrddataupSpec {
    type Ux = u32;
    const OFFSET: u64 = 164u64;
}
#[doc = "`read()` method returns [`flashcmdrddataup::R`](R) reader structure"]
impl crate::Readable for FlashcmdrddataupSpec {}
#[doc = "`write(|w| ..)` method takes [`flashcmdrddataup::W`](W) writer structure"]
impl crate::Writable for FlashcmdrddataupSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets flashcmdrddataup to value 0"]
impl crate::Resettable for FlashcmdrddataupSpec {
    const RESET_VALUE: u32 = 0;
}
