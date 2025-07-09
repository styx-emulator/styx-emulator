// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RXDR` reader"]
pub type R = crate::R<RxdrSpec>;
#[doc = "Register `RXDR` writer"]
pub type W = crate::W<RxdrSpec>;
#[doc = "Field `RXDR` reader - CEC Rx Data Register"]
pub type RxdrR = crate::FieldReader;
#[doc = "Field `RXDR` writer - CEC Rx Data Register"]
pub type RxdrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - CEC Rx Data Register"]
    #[inline(always)]
    pub fn rxdr(&self) -> RxdrR {
        RxdrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - CEC Rx Data Register"]
    #[inline(always)]
    #[must_use]
    pub fn rxdr(&mut self) -> RxdrW<RxdrSpec> {
        RxdrW::new(self, 0)
    }
}
#[doc = "Rx Data Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxdrSpec;
impl crate::RegisterSpec for RxdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`rxdr::R`](R) reader structure"]
impl crate::Readable for RxdrSpec {}
#[doc = "`reset()` method sets RXDR to value 0"]
impl crate::Resettable for RxdrSpec {
    const RESET_VALUE: u32 = 0;
}
