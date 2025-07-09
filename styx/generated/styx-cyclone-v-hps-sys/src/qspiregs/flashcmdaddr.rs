// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `flashcmdaddr` reader"]
pub type R = crate::R<FlashcmdaddrSpec>;
#[doc = "Register `flashcmdaddr` writer"]
pub type W = crate::W<FlashcmdaddrSpec>;
#[doc = "Field `addr` reader - This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the address used by the command specified in the opcode field (bits 31:24) of the Flash Command Control register."]
pub type AddrR = crate::FieldReader<u32>;
#[doc = "Field `addr` writer - This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the address used by the command specified in the opcode field (bits 31:24) of the Flash Command Control register."]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the address used by the command specified in the opcode field (bits 31:24) of the Flash Command Control register."]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This should be setup before triggering the command with execute field (bit 0) of the Flash Command Control register. It is the address used by the command specified in the opcode field (bits 31:24) of the Flash Command Control register."]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<FlashcmdaddrSpec> {
        AddrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FlashcmdaddrSpec;
impl crate::RegisterSpec for FlashcmdaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`flashcmdaddr::R`](R) reader structure"]
impl crate::Readable for FlashcmdaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`flashcmdaddr::W`](W) writer structure"]
impl crate::Writable for FlashcmdaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets flashcmdaddr to value 0"]
impl crate::Resettable for FlashcmdaddrSpec {
    const RESET_VALUE: u32 = 0;
}
