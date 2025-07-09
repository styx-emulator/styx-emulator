// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `KR` reader"]
pub type R = crate::R<KrSpec>;
#[doc = "Register `KR` writer"]
pub type W = crate::W<KrSpec>;
#[doc = "Field `KEY` reader - Key value (write only, read 0000h)"]
pub type KeyR = crate::FieldReader<u16>;
#[doc = "Field `KEY` writer - Key value (write only, read 0000h)"]
pub type KeyW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Key value (write only, read 0000h)"]
    #[inline(always)]
    pub fn key(&self) -> KeyR {
        KeyR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Key value (write only, read 0000h)"]
    #[inline(always)]
    #[must_use]
    pub fn key(&mut self) -> KeyW<KrSpec> {
        KeyW::new(self, 0)
    }
}
#[doc = "Key register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`kr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct KrSpec;
impl crate::RegisterSpec for KrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`write(|w| ..)` method takes [`kr::W`](W) writer structure"]
impl crate::Writable for KrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets KR to value 0"]
impl crate::Resettable for KrSpec {
    const RESET_VALUE: u32 = 0;
}
