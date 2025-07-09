// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RXDR` reader"]
pub type R = crate::R<RxdrSpec>;
#[doc = "Register `RXDR` writer"]
pub type W = crate::W<RxdrSpec>;
#[doc = "Field `RXDATA` reader - 8-bit receive data"]
pub type RxdataR = crate::FieldReader;
#[doc = "Field `RXDATA` writer - 8-bit receive data"]
pub type RxdataW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - 8-bit receive data"]
    #[inline(always)]
    pub fn rxdata(&self) -> RxdataR {
        RxdataR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - 8-bit receive data"]
    #[inline(always)]
    #[must_use]
    pub fn rxdata(&mut self) -> RxdataW<RxdrSpec> {
        RxdataW::new(self, 0)
    }
}
#[doc = "Receive data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxdrSpec;
impl crate::RegisterSpec for RxdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`rxdr::R`](R) reader structure"]
impl crate::Readable for RxdrSpec {}
#[doc = "`reset()` method sets RXDR to value 0"]
impl crate::Resettable for RxdrSpec {
    const RESET_VALUE: u32 = 0;
}
