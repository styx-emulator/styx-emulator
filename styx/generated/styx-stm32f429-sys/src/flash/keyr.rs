// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `KEYR` reader"]
pub type R = crate::R<KeyrSpec>;
#[doc = "Register `KEYR` writer"]
pub type W = crate::W<KeyrSpec>;
#[doc = "Field `KEY` reader - FPEC key"]
pub type KeyR = crate::FieldReader<u32>;
#[doc = "Field `KEY` writer - FPEC key"]
pub type KeyW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - FPEC key"]
    #[inline(always)]
    pub fn key(&self) -> KeyR {
        KeyR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - FPEC key"]
    #[inline(always)]
    #[must_use]
    pub fn key(&mut self) -> KeyW<KeyrSpec> {
        KeyW::new(self, 0)
    }
}
#[doc = "Flash key register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`keyr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct KeyrSpec;
impl crate::RegisterSpec for KeyrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`write(|w| ..)` method takes [`keyr::W`](W) writer structure"]
impl crate::Writable for KeyrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets KEYR to value 0"]
impl crate::Resettable for KeyrSpec {
    const RESET_VALUE: u32 = 0;
}
