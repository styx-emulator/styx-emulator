// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `flashcmdwrdataup` reader"]
pub type R = crate::R<FlashcmdwrdataupSpec>;
#[doc = "Register `flashcmdwrdataup` writer"]
pub type W = crate::W<FlashcmdwrdataupSpec>;
#[doc = "Field `data` reader - This is the command write data upper byte. This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the data that is to be written to the flash for any status or configuration write operation carried out by triggering the event in the Flash Command Control register."]
pub type DataR = crate::FieldReader<u32>;
#[doc = "Field `data` writer - This is the command write data upper byte. This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the data that is to be written to the flash for any status or configuration write operation carried out by triggering the event in the Flash Command Control register."]
pub type DataW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This is the command write data upper byte. This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the data that is to be written to the flash for any status or configuration write operation carried out by triggering the event in the Flash Command Control register."]
    #[inline(always)]
    pub fn data(&self) -> DataR {
        DataR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This is the command write data upper byte. This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the data that is to be written to the flash for any status or configuration write operation carried out by triggering the event in the Flash Command Control register."]
    #[inline(always)]
    #[must_use]
    pub fn data(&mut self) -> DataW<FlashcmdwrdataupSpec> {
        DataW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdwrdataup::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdwrdataup::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FlashcmdwrdataupSpec;
impl crate::RegisterSpec for FlashcmdwrdataupSpec {
    type Ux = u32;
    const OFFSET: u64 = 172u64;
}
#[doc = "`read()` method returns [`flashcmdwrdataup::R`](R) reader structure"]
impl crate::Readable for FlashcmdwrdataupSpec {}
#[doc = "`write(|w| ..)` method takes [`flashcmdwrdataup::W`](W) writer structure"]
impl crate::Writable for FlashcmdwrdataupSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets flashcmdwrdataup to value 0"]
impl crate::Resettable for FlashcmdwrdataupSpec {
    const RESET_VALUE: u32 = 0;
}
